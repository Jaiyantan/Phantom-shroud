import requests
from urllib.parse import urlparse, urljoin
import re

def monitor_portal_redirects(session, url, logger, known_domains=None):
    known_domains = known_domains or set([urlparse(url).netloc])
    try:
        resp = session.get(url, allow_redirects=False, timeout=12)
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get('Location','')
            if any(x in loc.lower() for x in ['/login', '/portal', 'captive']):
                logger.log_event('portal_redirect', 'WARNING', {'url':url, 'location':loc, 'message':'Unexpected redirect to possible portal/login.'})
        # Parse forms after following redirect if any
        resp2 = session.get(url, timeout=12)
        for action, target in re.findall(r'<form[^>]*action=["\'](.*?)["\']', resp2.text, re.IGNORECASE):
            if target.strip():
                post_host = urlparse(urljoin(url, target)).netloc
                if post_host not in known_domains:
                    logger.log_event('portal_redirect', 'WARNING', {'url':url, 'action':target, 'post_host':post_host, 'message':'Form posts to an unknown/suspicious domain.'})
    except Exception as e:
        logger.log_event('portal_redirect', 'ERROR', {'url':url, 'error':str(e)})
