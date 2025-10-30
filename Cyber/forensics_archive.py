import os
import time
import hashlib
from urllib.parse import urlparse
DEF_DIR = './forensics/'
os.makedirs(DEF_DIR, exist_ok=True)

def archive_forensics(url, body, meta, logger):
    ts = int(time.time())
    h = hashlib.sha256(body).hexdigest()[:10]
    domain = urlparse(url).netloc.replace(':', '_')
    fn = f'{DEF_DIR}{domain}_{ts}_{h}.bin'
    with open(fn, 'wb') as f:
        f.write(body)
        if meta:
            f.write(f"\n<!-- {meta} -->\n".encode())
    logger.log_event('forensics_archive', 'INFO', {'url': url,'meta': str(meta), 'archive': fn, 'message':'Resource/body archived for incident review.'})
