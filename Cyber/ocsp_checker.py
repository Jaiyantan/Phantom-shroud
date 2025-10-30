import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import AuthorityInformationAccessOID
import base64
import time

def check_ocsp_status(cert_pem, issuer_pem, logger):
    # Loads both certs
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        issuer = x509.load_pem_x509_certificate(issuer_pem.encode(), default_backend())
        aia = cert.extensions.get_extension_for_oid(AuthorityInformationAccessOID.AUTHORITY_INFORMATION_ACCESS)
        ocsp_urls = [d.access_location.value for d in aia.value if d.access_method == AuthorityInformationAccessOID.OCSP]
        if not ocsp_urls:
            logger.log_event('ocsp_checker', 'WARNING', {'serial': str(cert.serial_number), 'message': 'No OCSP URL present in cert'})
            return 'unknown'
        # Build OCSP request
        from cryptography.x509.ocsp import OCSPRequestBuilder
        builder = OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, cert.signature_hash_algorithm)
        req = builder.build()
        content = req.public_bytes(encoding=None)
        url = ocsp_urls[0]
        headers = {'Content-Type': 'application/ocsp-request'}
        resp = requests.post(url, data=content, headers=headers, timeout=10)
        if resp.status_code != 200:
            logger.log_event('ocsp_checker', 'ERROR', {'serial': str(cert.serial_number), 'message': f'OCSP HTTP error {resp.status_code}'})
            return 'unknown'
        from cryptography.x509.ocsp import load_der_ocsp_response
        ocsp_resp = load_der_ocsp_response(resp.content)
        status = ocsp_resp.certificate_status
        logger.log_event('ocsp_checker', 'INFO', {
            'serial': str(cert.serial_number),
            'status': str(status),
            'update_time': time.time(),
            'message': 'OCSP status checked for cert'
        })
        if str(status).lower() == 'revoked':
            logger.log_event('ocsp_checker', 'CRITICAL', {
                'serial': str(cert.serial_number), 'message': 'Presented certificate is REVOKED! MITM likely.'
            })
        return status
    except Exception as e:
        logger.log_event('ocsp_checker', 'ERROR', {'error': str(e)})
        return 'unknown'
