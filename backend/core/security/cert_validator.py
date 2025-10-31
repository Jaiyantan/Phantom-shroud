"""
Certificate Validator Module
Implements certificate pinning to detect MITM attacks.

Original Author: Joseph
Integrated into Phantom-shroud: October 31, 2025
"""

import threading
import hashlib
import logging
from typing import Optional, Dict, Callable
from datetime import datetime

logger = logging.getLogger(__name__)


class CertificateValidator:
    """
    Certificate pinning validator to detect certificate substitution attacks.
    
    Maintains a database of certificate pins (SHA-256 hashes) for domains
    and validates that certificates haven't changed unexpectedly.
    """
    
    def __init__(self, callback: Optional[Callable] = None):
        """
        Initialize Certificate Validator
        
        Args:
            callback: Function to call on certificate mismatch.
                     Signature: callback(domain: str, expected_pin: str, presented_pin: str)
        """
        self.callback = callback
        self._pins: Dict[str, Dict] = {}  # domain -> {pin, first_seen, last_seen}
        self._lock = threading.Lock()
        self._violations = []
    
    def pin_certificate(self, domain: str, cert_der: bytes, metadata: Optional[Dict] = None) -> str:
        """
        Pin a certificate for a domain
        
        Args:
            domain: Domain name
            cert_der: Certificate in DER format
            metadata: Optional metadata (issuer, expiry, etc.)
        
        Returns:
            SHA-256 hash of the certificate
        """
        pin = hashlib.sha256(cert_der).hexdigest()
        
        with self._lock:
            if domain not in self._pins:
                self._pins[domain] = {
                    'pin': pin,
                    'first_seen': datetime.now().isoformat(),
                    'last_seen': datetime.now().isoformat(),
                    'metadata': metadata or {}
                }
                logger.info(f"Certificate pinned for {domain}: {pin[:16]}...")
            else:
                # Update last seen
                self._pins[domain]['last_seen'] = datetime.now().isoformat()
                
                # Check if pin changed
                if self._pins[domain]['pin'] != pin:
                    logger.warning(
                        f"Certificate pin changed for {domain}: "
                        f"{self._pins[domain]['pin'][:16]}... -> {pin[:16]}..."
                    )
        
        return pin
    
    def validate_certificate(self, domain: str, cert_der: bytes) -> bool:
        """
        Validate a certificate against pinned value
        
        Args:
            domain: Domain name
            cert_der: Certificate in DER format
        
        Returns:
            True if valid, False if mismatch or not pinned
        """
        pin = hashlib.sha256(cert_der).hexdigest()
        
        with self._lock:
            pinned_data = self._pins.get(domain)
            
            if not pinned_data:
                # No pin exists - this is informational, not an error
                logger.debug(f"No certificate pin exists for {domain}")
                return True  # Allow but don't validate
            
            expected_pin = pinned_data['pin']
            
            if expected_pin != pin:
                # VIOLATION DETECTED
                violation = {
                    'domain': domain,
                    'expected_pin': expected_pin,
                    'presented_pin': pin,
                    'timestamp': datetime.now().isoformat(),
                    'message': 'Certificate pin mismatch - possible MITM attack',
                    'severity': 'CRITICAL'
                }
                
                self._violations.append(violation)
                
                logger.critical(
                    f"Certificate pin mismatch for {domain}!\n"
                    f"  Expected: {expected_pin[:16]}...\n"
                    f"  Got:      {pin[:16]}...\n"
                    f"  Possible MITM attack or certificate rotation"
                )
                
                # Trigger callback
                if self.callback:
                    try:
                        self.callback(domain, expected_pin, pin)
                    except Exception as e:
                        logger.error(f"Callback error: {e}")
                
                return False
            
            # Valid certificate
            pinned_data['last_seen'] = datetime.now().isoformat()
            return True
    
    def get_pin(self, domain: str) -> Optional[str]:
        """Get pinned certificate hash for domain"""
        with self._lock:
            data = self._pins.get(domain)
            return data['pin'] if data else None
    
    def get_all_pins(self) -> Dict[str, Dict]:
        """Get all pinned certificates"""
        with self._lock:
            return {domain: dict(data) for domain, data in self._pins.items()}
    
    def remove_pin(self, domain: str) -> bool:
        """Remove certificate pin for domain"""
        with self._lock:
            if domain in self._pins:
                del self._pins[domain]
                logger.info(f"Certificate pin removed for {domain}")
                return True
            return False
    
    def get_violations(self, limit: int = 50) -> list:
        """Get recent certificate violations"""
        with self._lock:
            return self._violations[-limit:]
    
    def clear_violations(self):
        """Clear violation history"""
        with self._lock:
            self._violations = []
        logger.info("Certificate violations cleared")
    
    def update_pin(self, domain: str, cert_der: bytes, force: bool = False) -> bool:
        """
        Update pinned certificate (use with caution)
        
        Args:
            domain: Domain name
            cert_der: New certificate in DER format
            force: Force update even if not pinned
        
        Returns:
            True if updated successfully
        """
        pin = hashlib.sha256(cert_der).hexdigest()
        
        with self._lock:
            if domain not in self._pins and not force:
                logger.warning(f"Cannot update non-existent pin for {domain}")
                return False
            
            old_pin = self._pins.get(domain, {}).get('pin', 'N/A')
            
            self._pins[domain] = {
                'pin': pin,
                'first_seen': self._pins.get(domain, {}).get('first_seen', datetime.now().isoformat()),
                'last_seen': datetime.now().isoformat(),
                'metadata': self._pins.get(domain, {}).get('metadata', {})
            }
            
            logger.warning(
                f"Certificate pin updated for {domain}: "
                f"{old_pin[:16] if old_pin != 'N/A' else 'N/A'}... -> {pin[:16]}..."
            )
            return True


# Backward compatibility with Joseph's original interface
_global_pins = {}
_pins_lock = threading.Lock()

def pin_cert(domain: str, cert_der: bytes):
    """Legacy interface for compatibility"""
    h = hashlib.sha256(cert_der).hexdigest()
    with _pins_lock:
        _global_pins[domain] = h
    logger.info(f"Certificate pinned (legacy): {domain} -> {h[:16]}...")

def check_cert(domain: str, cert_der: bytes, logger_obj) -> bool:
    """Legacy interface for compatibility"""
    h = hashlib.sha256(cert_der).hexdigest()
    with _pins_lock:
        pinned = _global_pins.get(domain)
        if pinned and pinned != h:
            if hasattr(logger_obj, 'log_event'):
                logger_obj.log_event('cert_pinning', 'CRITICAL', {
                    'domain': domain,
                    'message': 'Certificate pin mismatch. Possible MITM/cert forgery.',
                    'expected_pin': pinned,
                    'presented_pin': h
                })
            return False
    return True
