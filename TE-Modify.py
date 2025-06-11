def detect_smuggling(headers, body, method):
    te_headers = [k for k in headers.keys() if k.lower() == 'transfer-encoding']
    cl_headers = [k for k in headers.keys() if k.lower() == 'content-length']

    # ... previous checks ...

    if te_headers:
        te_value = headers[te_headers[0]].strip().lower()
        if te_value not in ['chunked', 'identity', '']:
            return True, f'Unusual Transfer-Encoding value: {te_value}'
        # Only enforce chunked body ending for methods that expect a body
        if te_value == 'chunked' and method in ['POST', 'PUT', 'PATCH']:
            if not body.endswith(b'0\r\n\r\n'):
                return True, 'Transfer-Encoding chunked without proper chunked body ending.'

    # ... rest of the logic ...
