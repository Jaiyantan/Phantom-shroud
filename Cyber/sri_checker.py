import re
import hashlib
import base64
import requests
from urllib.parse import urljoin

def check_sri_for_html(url, html, logger, known_sri_map=None):
    script_tags = re.findall(r'<script [^>]*src=["\'](.*?)["\'][^>]*>', html, re.IGNORECASE)
    for tag in script_tags:
        src_match = re.search(r'src=["\'](.*?)["\']', tag)
        int_match = re.search(r'integrity=["\'](.*?)["\']', tag)
        if src_match:
            src = src_match.group(1)
            full_url = urljoin(url, src)
            try:
                script = requests.get(full_url, timeout=10).content
                actual_hash = base64.b64encode(hashlib.sha256(script).digest()).decode()
                if int_match:
                    found_sri = int_match.group(1)
                    if not found_sri.endswith(actual_hash):
                        logger.log_event('sri_checker', 'WARNING', {
                            'src': src,
                            'message': 'SRI hash mismatch! Found/Computed:',
                            'found': found_sri,
                            'expected': f'sha256-{actual_hash}'
                        })
                    else:
                        logger.log_event('sri_checker', 'INFO', {'src': src, 'message': 'SRI hash verified.'})
                else:
                    logger.log_event('sri_checker', 'WARNING', {'src': src, 'message': 'No SRI present on script include.'})
                    if known_sri_map is not None:
                        known_sri_map[src] = actual_hash
            except Exception as e:
                logger.log_event('sri_checker', 'ERROR', {'src': src, 'error': str(e)})
