import threading
import time
import random
import string
_token_db = {}
_token_lock = threading.Lock()
TOKEN_TTL = 86400  # 1 day lifetime

def issue_honeytoken(context=None):
    token = ''.join(random.choices(string.ascii_letters+string.digits, k=12))
    with _token_lock:
        _token_db[token] = {'issued': time.time(), 'context': context}
    return token

def check_honeytoken(token, logger, context=None):
    with _token_lock:
        rec = _token_db.get(token)
        if rec:
            if time.time() - rec['issued'] > TOKEN_TTL:
                del _token_db[token]
                return False
            logger.log_event('honeytoken', 'CRITICAL', {
                'token': token, 'issued_at': rec['issued'], 'detected_context': context, 'message': 'Honeytoken reuse detected!'}
            )
            return True
    return False
