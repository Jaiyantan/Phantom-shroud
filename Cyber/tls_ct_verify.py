import requests
import hashlib
import time
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def fetch_ct_logs(cert_pem, logger):
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        serial = format(cert.serial_number, 'x')
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        ct_api_url = f"https://crt.sh/?q={serial}&output=json"
        resp = requests.get(ct_api_url, timeout=10)
        if resp.status_code == 200 and resp.json():
            logger.log_event('tls_ct_verify', 'INFO', {
                'serial': serial,
                'subject': subject,
                'issuer': issuer,
                'ct_entries': [x.get('common_name') for x in resp.json()],
                'message': 'Cert found in CT logs'}
            )
            return True
        else:
            logger.log_event('tls_ct_verify', 'WARNING', {
                'serial': serial,
                'subject': subject,
                'issuer': issuer,
                'message': 'No matching entry in public CT logs - possible private/forged cert!'}
            )
            return False
    except Exception as e:
        logger.log_event('tls_ct_verify', 'ERROR', {'message': 'Failed CT log check', 'error': str(e)})
        return False
