import hashlib
import re
_fingerprints = {}

def fingerprint_portal(html, logger, region_hint=None):
    # Simple: hash visible DOM + <style>/<link rel=stylesheet>
    norm = re.sub(r'\s+', ' ', re.sub(r'<script[\s\S]*?</script>', '', html, flags=re.IGNORECASE))
    style = ''.join(re.findall(r'<style[\s\S]*?</style>', html, re.IGNORECASE))
    total = (norm + style).encode()
    dom_hash = hashlib.sha256(total).hexdigest()[:14]
    region = region_hint or 'unknown'
    info = {'portal_dom_hash': dom_hash, 'region': region}
    snippet = norm[:60].replace('\n',' ')
    prior = _fingerprints.get(dom_hash)
    if prior and prior != region:
        logger.log_event('portal_fingerprint', 'WARNING', {'message':'Login/captive portal fingerprint reused in new region.', 'hash': dom_hash, 'prev_region': prior, 'region': region, 'snippet': snippet})
    _fingerprints[dom_hash] = region
    logger.log_event('portal_fingerprint', 'INFO', {'message': 'Portal fingerprint recorded', 'hash': dom_hash, 'region': region, 'snippet': snippet})
    return dom_hash
