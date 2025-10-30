import http.server
import socketserver
import threading
import time

HONEYPOT_PAYLOAD = '''
// PrivacyGuard exfil/modify beacon
(function(){
    var payload = {
        t: Date.now(),
        user: navigator.userAgent,
        rand: Math.random(),
        location: window.location.href,
        det: 'executed',
    };
    fetch("__BEACON_URL__", {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
    });
})();
'''

class JSExfilHoneypotServer(http.server.BaseHTTPRequestHandler):
    _beacon_url = ''
    _logger = None
    def do_GET(self):
        if self.path.startswith('/honey.js'):
            code = HONEYPOT_PAYLOAD.replace('__BEACON_URL__', self._beacon_url)
            self.send_response(200)
            self.send_header('Content-Type', 'application/javascript')
            self.end_headers()
            self.wfile.write(code.encode())
            self._logger.log_event('js_exfil_honeypot', 'INFO', {
                'event': 'served_honeyjs', 'ip': self.client_address[0], 'user-agent': self.headers.get('User-Agent'), 'timestamp': time.time()})
        else:
            self.send_response(404)
            self.end_headers()
    def do_POST(self):
        if self.path.startswith('/beacon'):
            length = int(self.headers.get('Content-Length','0'))
            body = self.rfile.read(length)
            self._logger.log_event('js_exfil_honeypot', 'CRITICAL', {
                'event': 'beacon_cb', 'src_ip': self.client_address[0], 'json': body.decode(), 'timestamp': time.time()})
            self.send_response(200)
            self.end_headers()

def start_js_exfil_honeypot(port, logger):
    handler = JSExfilHoneypotServer
    handler._beacon_url = f'http://localhost:{port}/beacon'
    handler._logger = logger
    server = socketserver.ThreadingTCPServer(('0.0.0.0', port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    logger.log_event('js_exfil_honeypot', 'INFO', {'message': f'JS exfil honeypot started on :{port}'})
    return server
