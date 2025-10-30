import http.server
import socketserver
import threading
import time
import random
import string
HONEY_FORM = '''\
<html><body><h2>Wi-Fi Login Portal</h2>
<form method="POST">Username: <input name="user"><br>Password: <input name="pass"><br><input type="hidden" name="token" value="{token}">
<input type="submit" value="Login"></form></body></html>'''
RESULT_PAGE = '<html><body><h2>Thank you.</h2><p>This is a safe sandbox login. Credential use is blocked. If this portal appeared unexpectedly, contact your IT department immediately.</p></body></html>'

class FakePortalHandler(http.server.BaseHTTPRequestHandler):
    _logger = None
    _honeytokens = None
    def do_GET(self):
        token = ''.join(random.choices(string.ascii_letters+string.digits, k=10))
        if self._honeytokens is not None:
            self._honeytokens[token] = {'issued': time.time()}
        self.send_response(200)
        self.send_header('Content-Type','text/html')
        self.end_headers()
        self.wfile.write(HONEY_FORM.format(token=token).encode())
        self._logger.log_event('fake_portal', 'INFO', {'event':'served_portal', 'ip':self.client_address[0], 'token':token})
    def do_POST(self):
        length = int(self.headers.get('Content-Length','0'))
        post = self.rfile.read(length)
        fields = dict([kv.split('=') for kv in post.decode(errors='ignore').split('&') if '=' in kv])
        self._logger.log_event('fake_portal', 'CRITICAL', {'event':'captured_login', 'headers':dict(self.headers), 'fields':fields, 'remote_ip':self.client_address[0], 'token':fields.get('token','')})
        self.send_response(200)
        self.send_header('Content-Type','text/html')
        self.end_headers()
        self.wfile.write(RESULT_PAGE.encode())

def start_fake_portal_server(port, logger, honeytokens=None):
    handler = FakePortalHandler
    handler._logger = logger
    handler._honeytokens = honeytokens or {}
    httpd = socketserver.ThreadingTCPServer(('0.0.0.0', port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    logger.log_event('fake_portal', 'INFO', {'message': f'Fake captive portal server running on :{port}'})
    return httpd
