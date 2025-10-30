import re
from urllib.parse import urlparse, urljoin
import hashlib

def parse_and_log_scripts(url, html, logger, seen_domains=None, seen_scripts=None):
    if seen_domains is None:
        seen_domains = set()
    if seen_scripts is None:
        seen_scripts = set()
    scripts = re.findall(r'<script [^>]*src=["\'](.*?)["\'][^>]*>', html, re.IGNORECASE)
    inlines = re.findall(r'<script(?: [^>]*)?>([\s\S]*?)</script>', html, re.IGNORECASE)
    base = urlparse(url).netloc
    for src in scripts:
        dom = urlparse(urljoin(url, src)).netloc
        if dom not in seen_domains:
            logger.log_event('script_domain_monitor', 'WARNING', {'domain': dom, 'src': src, 'message': 'New script domain seen on page.'})
            seen_domains.add(dom)
    for script in inlines:
        h = hashlib.sha256(script.encode()).hexdigest()
        if h not in seen_scripts:
            snippet = script.strip()[:40].replace('\n', ' ')
            logger.log_event('script_domain_monitor', 'INFO', {'message': 'New inline <script> block (hash, snippet)', 'hash': h, 'code': snippet})
            seen_scripts.add(h)
    return seen_domains, seen_scripts
