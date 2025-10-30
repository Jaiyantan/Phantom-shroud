import socket, ssl
import threading
import time

def start_tls_honeypot(port, certfile, keyfile, logger):
    def worker():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(5)
        logger.log_event('tls_honeypot', 'INFO', {'port': port, 'message': 'TLS honeypot started'})
        while True:
            client, addr = sock.accept()
            threading.Thread(target=handle, args=(client, addr), daemon=True).start()

    def handle(client, addr):
        info = {'timestamp': time.time(), 'src_ip': addr[0], 'src_port': addr[1], 'message': 'TLS honeypot connection'}
        try:
            tls = context.wrap_socket(client, server_side=True)
            info['sni'] = tls.server_hostname
            info['cipher'] = tls.cipher()
            data = tls.recv(1024)
            sample = data[:200].decode(errors='ignore') if data else ''
            info['data_sample'] = sample
            if b'GET' in data:
                tls.send(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Site Under Test: TLS Proxy detected</h1>')
        except Exception as e:
            info['error'] = str(e)
        logger.log_event('tls_honeypot', 'INFO', info)
        try:
            client.close()
        except:
            pass
    threading.Thread(target=worker, daemon=True).start()
