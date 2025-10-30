import requests
import threading
import time
import hashlib
import os
from urllib.parse import urlparse
_mon_thread = None
_running = False
_last_snapshots = {}
ARCHIVE_DIR = './content_diff_archives'

def start_content_diff_monitor(config, logger):
    global _mon_thread, _running
    if not hasattr(config, 'content_diff_targets') or not config.content_diff_targets:
        logger.log_event('content_diff', 'WARNING', {'message': 'No target URLs configured for content diff.'})
        return
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    _running = True
    _mon_thread = threading.Thread(target=_monitor, args=(config, logger), daemon=True)
    _mon_thread.start()
    logger.log_event('content_diff', 'INFO', {'message': 'Content diff monitor started.'})

def stop_content_diff_monitor():
    global _running, _mon_thread
    _running = False
    if _mon_thread:
        _mon_thread.join(timeout=2)

def _monitor(config, logger):
    delay = getattr(config, 'content_diff_interval', 300)
    while _running:
        for url in getattr(config, 'content_diff_targets', []):
            try:
                resp = requests.get(url, timeout=15)
                if resp.status_code == 200:
                    content = resp.content
                    prev = _last_snapshots.get(url)
                    if prev and content != prev:
                        logger.log_event('content_diff', 'ERROR', {
                            'url': url,
                            'message': 'Content diff detected! Archive created.',
                            'first_bytes': content[:80] if content else b''
                        })
                        _archive_resource(url, content, logger)
                    _last_snapshots[url] = content
                else:
                    logger.log_event('content_diff', 'WARNING', {'url': url, 'message': f'HTTP error {resp.status_code} during fetch.'})
            except Exception as e:
                logger.log_event('content_diff', 'ERROR', {'url': url, 'error': str(e)})
        time.sleep(delay)

def _archive_resource(url, content, logger):
    ts = int(time.time())
    domain = urlparse(url).netloc.replace(':', '_')
    h = hashlib.sha256(content).hexdigest()[:10]
    fn = f'{ARCHIVE_DIR}/{domain}_{ts}_{h}.bin'
    with open(fn, 'wb') as f:
        f.write(content)
    logger.log_event('content_diff', 'INFO', {'url': url, 'archive': fn, 'message': 'Archived changed content.'})
