import time

def log_connection(logger, src_ip, src_port, dest_port, banner, tcp_options=None, user_agent=None, data_sample=None):
    evt = {
        'timestamp': time.time(),
        'src_ip': src_ip,
        'src_port': src_port,
        'dest_port': dest_port,
        'banner': banner,
        'tcp_options': tcp_options if tcp_options else {},
        'user_agent': user_agent,
        'data_sample': data_sample[:200] if data_sample else None
    }
    logger.log_event('honeypot_fingerprint', 'INFO', evt)
