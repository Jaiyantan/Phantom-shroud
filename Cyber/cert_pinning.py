import threading
import hashlib

_pins = {}
_pins_lock = threading.Lock()

def pin_cert(domain, cert_der):
    global _pins
    h = hashlib.sha256(cert_der).hexdigest()
    with _pins_lock:
        _pins[domain] = h

def check_cert(domain, cert_der, logger):
    h = hashlib.sha256(cert_der).hexdigest()
    with _pins_lock:
        pinned = _pins.get(domain)
        if pinned and pinned != h:
            logger.log_event('cert_pinning', 'CRITICAL', {
                'domain': domain,
                'message': 'Certificate pin mismatch. Possible MITM/cert forgery.',
                'expected_pin': pinned,
                'presented_pin': h
            })
            return False
    return True
