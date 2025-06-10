import http.server
import socketserver
import requests
import re
import logging
from io import BytesIO

FORWARD_URL = 'http://localhost:7070'  # Go frontend
LISTEN_PORT = 7070

# Configure logging
logging.basicConfig(filename='waf_smuggling.log', level=logging.INFO, format='%(asctime)s %(message)s')

# Regex patterns for obfuscated headers
TE_OBFUSCATED = re.compile(r'transfer[\s_\-]*encoding\s*:', re.IGNORECASE)
CL_OBFUSCATED = re.compile(r'content[\s_\-]*length\s*:', re.IGNORECASE)

def detect_smuggling(headers, body):
    """
    Returns (is_smuggling_detected, reason)
    """
    header_names = [k.lower() for k in headers.keys()]
    te_headers = [k for k in headers.keys() if k.lower() == 'transfer-encoding']
    cl_headers = [k for k in headers.keys() if k.lower() == 'content-length']

    # 1. CL.TE or TE.CL: Both headers present
    if te_headers and cl_headers:
        te_value = headers[te_headers[0]].lower()
        cl_value = headers[cl_headers[0]]
        if 'chunked' in te_value:
            # Check for CL.TE or TE.CL
            return True, f'Both Content-Length ({cl_value}) and Transfer-Encoding ({te_value}) headers present.'

    # 2. Multiple TE or CL headers (TE.TE, CL.CL)
    if len(te_headers) > 1 or len(cl_headers) > 1:
        return True, 'Multiple Transfer-Encoding or Content-Length headers detected.'

    # 3. Obfuscated TE/CL headers (e.g., Transfer_Encoding, Transfer-Encoding with whitespace)
    for raw_header in headers:
        if TE_OBFUSCATED.match(raw_header):
            return True, f'Obfuscated Transfer-Encoding header: {raw_header}'
        if CL_OBFUSCATED.match(raw_header):
            return True, f'Obfuscated Content-Length header: {raw_header}'

    # 4. Invalid/malformed TE or CL values
    if te_headers:
        te_value = headers[te_headers[0]].strip().lower()
        if te_value not in ['chunked', 'identity', '']:
            return True, f'Unusual Transfer-Encoding value: {te_value}'
        # Check for chunked body format if chunked
        if te_value == 'chunked' and not body.endswith(b'0\r\n\r\n'):
            return True, 'Transfer-Encoding chunked without proper chunked body ending.'

    if cl_headers:
        try:
            cl_value = int(headers[cl_headers[0]].strip())
            if cl_value != len(body):
                return True, f'Content-Length mismatch: header={cl_value}, actual={len(body)}'
        except Exception:
            return True, f'Invalid Content-Length value: {headers[cl_headers[0]]}'

    # 5. Duplicate or conflicting headers (e.g., both Transfer-Encoding: chunked, identity)
    if te_headers:
        te_value = headers[te_headers[0]].lower()
        if ',' in te_value and 'chunked' in te_value and 'identity' in te_value:
            return True, f'Conflicting Transfer-Encoding values: {te_value}'

    # 6. Non-standard line endings or header delimiters (CRLF injection)
    # Not directly visible via headers dict, but can be checked in raw request parsing (advanced)

    return False, ''

class WAFRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.handle_request()
    def do_GET(self):
        self.handle_request()
    def do_PUT(self):
        self.handle_request()
    def do_DELETE(self):
        self.handle_request()
    def do_OPTIONS(self):
        self.handle_request()

    def handle_request(self):
        # Read request headers and body
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''

        # Detect smuggling
        detected, reason = detect_smuggling(self.headers, body)
        if detected:
            log_entry = f"[WAF] HTTP Request Smuggling detected: {reason} | Path: {self.path} | Headers: {dict(self.headers)}"
            logging.warning(log_entry)
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"WAF: HTTP Request Smuggling detected.\n")
            return

        # Forward request to Go frontend
        try:
            # Prepare headers for forwarding
            forward_headers = {k: v for k, v in self.headers.items()}
            resp = requests.request(
                method=self.command,
                url=FORWARD_URL + self.path,
                headers=forward_headers,
                data=body,
                allow_redirects=False,
                timeout=10
            )
            self.send_response(resp.status_code)
            for k, v in resp.headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp.content)
        except Exception as e:
            logging.error(f"[WAF] Error forwarding request: {e}")
            self.send_response(502)
            self.end_headers()
            self.wfile.write(b"WAF: Error forwarding request.\n")

if __name__ == '__main__':
    with socketserver.ThreadingTCPServer(('', LISTEN_PORT), WAFRequestHandler) as httpd:
        print(f'[WAF] Listening on port {LISTEN_PORT}...')
        httpd.serve_forever()
