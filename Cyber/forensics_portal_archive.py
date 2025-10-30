import os
import time
import hashlib
import json
from urllib.parse import urlparse
ARCHIVE_DIR = './forensics_portal/'
os.makedirs(ARCHIVE_DIR, exist_ok=True)

def archive_portal_event(url, html, post_data, logger, meta=None):
    ts = int(time.time())
    domain = urlparse(url).netloc.replace(':', '_')
    base = html.encode() if html else b''
    pdata = json.dumps(post_data or {}, sort_keys=True).encode()
    all_bytes = base + b'\nPOST:' + pdata
    h = hashlib.sha256(all_bytes).hexdigest()[:10]
    fn = f'{ARCHIVE_DIR}{domain}_{ts}_{h}.bin'
    with open(fn, 'wb') as f:
        f.write(all_bytes)
        if meta:
            f.write(f"\n<!-- {meta} -->\n".encode())
    logger.log_event('forensics_portal', 'INFO', {'url': url, 'archive': fn, 'meta': meta, 'message':'Portal event archived.'})
