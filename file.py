#!/usr/bin/env python3
import asyncio
import argparse
import logging
import sys
import re
from datetime import datetime
from httptools import HttpRequestParser

# ------------------ CONFIGURATION ------------------

DEFAULT_LISTEN_PORT = 7070
DEFAULT_BACKEND_HOST = '127.0.0.1'
DEFAULT_BACKEND_PORT = 7071

# ------------------ LOGGING SETUP ------------------

logger = logging.getLogger("pywaf")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

# ------------------ RULE ENGINE ------------------

class DetectionRule:
    def __init__(self, name, pattern, description, block_on_detect=True):
        self.name = name
        self.pattern = pattern
        self.description = description
        self.block_on_detect = block_on_detect

    def match(self, headers, raw_request):
        return self.pattern(headers, raw_request)

def rule_cl_te(headers, raw_request):
    # Both Content-Length and Transfer-Encoding present
    return 'content-length' in headers and 'transfer-encoding' in headers

def rule_te_cl(headers, raw_request):
    # Both Transfer-Encoding and Content-Length present (same as above but for clarity)
    return 'transfer-encoding' in headers and 'content-length' in headers

def rule_cl_cl(headers, raw_request):
    # Duplicate Content-Length headers
    return len([k for k in headers_raw_list(raw_request) if k.lower() == 'content-length']) > 1

def rule_te_te(headers, raw_request):
    # Duplicate Transfer-Encoding headers
    return len([k for k in headers_raw_list(raw_request) if k.lower() == 'transfer-encoding']) > 1

def rule_obfuscated_headers(headers, raw_request):
    # Obfuscated headers: extra spaces, tabs, line folding, non-printable, null bytes
    obf_pattern = re.compile(rb'^(?:[^\r\n:]+)[ \t]+:', re.MULTILINE)
    null_bytes = b'\x00' in raw_request
    folding = re.search(rb'\r\n[ \t]+', raw_request)
    return bool(obf_pattern.search(raw_request) or null_bytes or folding)

def headers_raw_list(raw_request):
    # Extracts raw header names from the raw request bytes
    headers = []
    lines = raw_request.split(b'\r\n')
    for line in lines[1:]:
        if not line or b':' not in line:
            break
        header = line.split(b':', 1)[0].decode('latin1', errors='replace')
        headers.append(header)
    return headers

DETECTION_RULES = [
    DetectionRule("CL-TE", rule_cl_te, "Both Content-Length and Transfer-Encoding headers present"),
    DetectionRule("TE-CL", rule_te_cl, "Both Transfer-Encoding and Content-Length headers present"),
    DetectionRule("CL-CL", rule_cl_cl, "Duplicate Content-Length headers"),
    DetectionRule("TE-TE", rule_te_te, "Duplicate Transfer-Encoding headers"),
    DetectionRule("Obfuscated-Headers", rule_obfuscated_headers, "Obfuscated or malformed headers"),
]

# ------------------ CONFIGURATION HANDLING ------------------

class WAFConfig:
    def __init__(self, args):
        self.listen_port = args.listen_port
        self.backend_host = args.backend_host
        self.backend_port = args.backend_port
        self.log_all = args.log_all
        self.block = args.block
        self.rules = DETECTION_RULES

# ------------------ HTTP PARSING ------------------

class HTTPRequest:
    def __init__(self):
        self.method = None
        self.url = None
        self.headers = {}
        self.body = b''
        self.complete = False
        self.raw = b''

    def on_url(self, url):
        self.url = url

    def on_header(self, name, value):
        self.headers[name.lower()] = value

    def on_headers_complete(self):
        pass

    def on_body(self, body):
        self.body += body

    def on_message_complete(self):
        self.complete = True

def parse_http_request(data):
    req = HTTPRequest()
    parser = HttpRequestParser(req)
    try:
        parser.feed_data(data)
    except Exception as e:
        logger.warning(f"Failed to parse HTTP request: {e}")
    return req

def extract_headers(raw_request):
    # Returns dict of headers from raw request bytes
    headers = {}
    lines = raw_request.split(b'\r\n')
    for line in lines[1:]:
        if not line or b':' not in line:
            break
        k, v = line.split(b':', 1)
        headers[k.strip().lower().decode('latin1')] = v.strip().decode('latin1', errors='replace')
    return headers

# ------------------ DETECTION ENGINE ------------------

def detect_attack(headers, raw_request, rules):
    detected = []
    for rule in rules:
        if rule.match(headers, raw_request):
            detected.append(rule)
    return detected

# ------------------ PROXY LOGIC ------------------

class WAFProxy(asyncio.Protocol):
    def __init__(self, config):
        self.config = config
        self.transport = None
        self.peername = None
        self.buffer = b''
        self.headers = {}
        self.request_detected = False

    def connection_made(self, transport):
        self.transport = transport
        self.peername = transport.get_extra_info('peername')

    def data_received(self, data):
        self.buffer += data
        # Try to parse a complete HTTP request
        if b'\r\n\r\n' not in self.buffer:
            return  # Wait for more data

        # Parse headers and body
        headers = extract_headers(self.buffer)
        req_obj = parse_http_request(self.buffer)
        detected_rules = detect_attack(headers, self.buffer, self.config.rules)
        attack_detected = len(detected_rules) > 0

        # Logging
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        src_ip = self.peername[0] if self.peername else 'unknown'
        status = "SUSPICIOUS" if attack_detected else "BENIGN"
        logger.info(f"[{now}] {src_ip} {status} Request: {req_obj.method} {req_obj.url}")

        if self.config.log_all or attack_detected:
            logger.info(f"Headers: {headers}")
            if attack_detected:
                logger.warning(f"Attack Detected: {[r.name for r in detected_rules]}")

        # Terminal printout
        print(f"\n[{now}] {src_ip} {status} - {req_obj.method} {req_obj.url}")
        if attack_detected:
            print(f"  >> Detected: {[r.name for r in detected_rules]}")

        # Block or forward
        if attack_detected and self.config.block:
            self.transport.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            self.transport.close()
            return

        # Forward to backend
        asyncio.create_task(self.forward_to_backend(self.buffer))

    async def forward_to_backend(self, request_data):
        try:
            reader, writer = await asyncio.open_connection(
                self.config.backend_host, self.config.backend_port
            )
            writer.write(request_data)
            await writer.drain()
            response = await reader.read(65536)
            self.transport.write(response)
            self.transport.close()
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logger.error(f"Error forwarding to backend: {e}")
            self.transport.close()

# ------------------ MAIN ------------------

def parse_args():
    parser = argparse.ArgumentParser(description="Async Python WAF for HTTP Request Smuggling Detection")
    parser.add_argument('--listen-port', type=int, default=DEFAULT_LISTEN_PORT, help='Port to listen on (default: 7070)')
    parser.add_argument('--backend-host', type=str, default=DEFAULT_BACKEND_HOST, help='Backend server host (default: 127.0.0.1)')
    parser.add_argument('--backend-port', type=int, default=DEFAULT_BACKEND_PORT, help='Backend server port (default: 8080)')
    parser.add_argument('--log-all', action='store_true', help='Log all requests, not just attacks')
    parser.add_argument('--block', action='store_true', help='Block detected attacks (otherwise forward)')
    return parser.parse_args()

def main():
    args = parse_args()
    config = WAFConfig(args)
    loop = asyncio.get_event_loop()
    server_coro = loop.create_server(lambda: WAFProxy(config), '0.0.0.0', config.listen_port)
    server = loop.run_until_complete(server_coro)
    logger.info(f"WAF listening on 0.0.0.0:{config.listen_port}, forwarding to {config.backend_host}:{config.backend_port}")
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logger.info("WAF shutting down...")
    finally:
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()

if __name__ == "__main__":
    main()
