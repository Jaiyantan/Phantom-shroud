"""
Portal Detector Module
Detects and fingerprints captive portals and login pages.

Original Author: Joseph
Integrated into Phantom-shroud: October 31, 2025
"""

import hashlib
import re
import logging
from typing import Optional, Dict, Callable
from datetime import datetime
import threading

logger = logging.getLogger(__name__)


class PortalDetector:
    """
    Detects and fingerprints captive portals and login pages.
    
    Creates DOM-based fingerprints to identify when the same portal
    appears in different regions/networks, which may indicate attacks.
    """
    
    def __init__(self, callback: Optional[Callable] = None):
        """
        Initialize Portal Detector
        
        Args:
            callback: Function to call on suspicious portal reuse.
                     Signature: callback(portal_hash: str, region: str, details: dict)
        """
        self.callback = callback
        self._fingerprints: Dict[str, Dict] = {}  # hash -> {region, first_seen, seen_count, urls}
        self._lock = threading.Lock()
        self._detections = []
    
    def fingerprint_portal(
        self,
        html: str,
        url: str,
        region: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Create fingerprint of a portal/login page
        
        Args:
            html: HTML content of the page
            url: URL of the page
            region: Region/network identifier (SSID, location, etc.)
            metadata: Additional metadata
        
        Returns:
            SHA-256 hash of the portal DOM
        """
        # Normalize HTML: remove scripts and excessive whitespace
        normalized = re.sub(
            r'\s+', ' ',
            re.sub(
                r'<script[\s\S]*?</script>',
                '',
                html,
                flags=re.IGNORECASE
            )
        )
        
        # Extract and include style information (layout matters)
        styles = ''.join(re.findall(
            r'<style[\s\S]*?</style>',
            html,
            re.IGNORECASE
        ))
        
        # Create fingerprint from normalized content + styles
        combined = (normalized + styles).encode('utf-8', errors='ignore')
        portal_hash = hashlib.sha256(combined).hexdigest()[:16]  # Use first 16 chars
        
        region = region or 'unknown'
        snippet = normalized[:80].replace('\n', ' ')
        
        with self._lock:
            existing = self._fingerprints.get(portal_hash)
            
            if existing:
                # Portal hash seen before
                existing['seen_count'] += 1
                existing['last_seen'] = datetime.now().isoformat()
                
                if region not in existing['regions']:
                    existing['regions'].add(region)
                
                if url not in existing['urls']:
                    existing['urls'].append(url)
                
                # Check if portal is being reused across regions (SUSPICIOUS)
                if len(existing['regions']) > 1 and region != 'unknown':
                    detection = {
                        'portal_hash': portal_hash,
                        'message': 'Portal fingerprint reused across multiple regions',
                        'regions': list(existing['regions']),
                        'current_region': region,
                        'url': url,
                        'snippet': snippet,
                        'timestamp': datetime.now().isoformat(),
                        'severity': 'WARNING'
                    }
                    
                    self._detections.append(detection)
                    
                    logger.warning(
                        f"Portal fingerprint {portal_hash} seen in multiple regions: "
                        f"{existing['regions']}"
                    )
                    
                    if self.callback:
                        try:
                            self.callback(portal_hash, region, detection)
                        except Exception as e:
                            logger.error(f"Callback error: {e}")
            else:
                # New portal fingerprint
                self._fingerprints[portal_hash] = {
                    'hash': portal_hash,
                    'regions': {region},
                    'first_seen': datetime.now().isoformat(),
                    'last_seen': datetime.now().isoformat(),
                    'seen_count': 1,
                    'urls': [url],
                    'snippet': snippet,
                    'metadata': metadata or {}
                }
                
                logger.info(
                    f"Portal fingerprint recorded: {portal_hash} "
                    f"(region: {region}, url: {url})"
                )
        
        return portal_hash
    
    def is_captive_portal(self, html: str, url: str) -> bool:
        """
        Heuristic check if page is a captive portal
        
        Args:
            html: HTML content
            url: URL of the page
        
        Returns:
            True if likely a captive portal
        """
        html_lower = html.lower()
        url_lower = url.lower()
        
        # Common captive portal indicators
        portal_indicators = [
            'captive', 'portal', 'login', 'welcome', 'wifi',
            'internet access', 'agree', 'accept terms',
            'hotspot', 'network authentication'
        ]
        
        # Check URL
        if any(indicator in url_lower for indicator in portal_indicators):
            return True
        
        # Check HTML content
        if any(indicator in html_lower for indicator in portal_indicators):
            # Additional check: look for forms
            if '<form' in html_lower:
                return True
        
        # Check for redirects to login/portal pages
        if 'location.href' in html_lower or 'window.location' in html_lower:
            if any(indicator in html_lower for indicator in ['login', 'portal', 'captive']):
                return True
        
        return False
    
    def get_fingerprint(self, portal_hash: str) -> Optional[Dict]:
        """Get fingerprint data for a specific hash"""
        with self._lock:
            data = self._fingerprints.get(portal_hash)
            if data:
                result = dict(data)
                result['regions'] = list(result['regions'])
                return result
            return None
    
    def get_all_fingerprints(self) -> Dict[str, Dict]:
        """Get all portal fingerprints"""
        with self._lock:
            result = {}
            for hash_val, data in self._fingerprints.items():
                result[hash_val] = dict(data)
                result[hash_val]['regions'] = list(data['regions'])
            return result
    
    def get_detections(self, limit: int = 50) -> list:
        """Get recent suspicious portal detections"""
        with self._lock:
            return self._detections[-limit:]
    
    def clear_detections(self):
        """Clear detection history"""
        with self._lock:
            self._detections = []
        logger.info("Portal detections cleared")
    
    def get_portals_by_region(self, region: str) -> list:
        """Get all portals seen in a specific region"""
        with self._lock:
            results = []
            for hash_val, data in self._fingerprints.items():
                if region in data['regions']:
                    result = dict(data)
                    result['regions'] = list(result['regions'])
                    results.append(result)
            return results


# Backward compatibility with Joseph's original interface
_global_fingerprints = {}

def fingerprint_portal(html: str, logger_obj, region_hint: Optional[str] = None) -> str:
    """Legacy interface for compatibility"""
    # Simple: hash visible DOM + styles
    norm = re.sub(
        r'\s+', ' ',
        re.sub(r'<script[\s\S]*?</script>', '', html, flags=re.IGNORECASE)
    )
    style = ''.join(re.findall(r'<style[\s\S]*?</style>', html, re.IGNORECASE))
    total = (norm + style).encode('utf-8', errors='ignore')
    dom_hash = hashlib.sha256(total).hexdigest()[:14]
    region = region_hint or 'unknown'
    
    snippet = norm[:60].replace('\n', ' ')
    prior = _global_fingerprints.get(dom_hash)
    
    if prior and prior != region:
        if hasattr(logger_obj, 'log_event'):
            logger_obj.log_event('portal_fingerprint', 'WARNING', {
                'message': 'Login/captive portal fingerprint reused in new region',
                'hash': dom_hash,
                'prev_region': prior,
                'region': region,
                'snippet': snippet
            })
    
    _global_fingerprints[dom_hash] = region
    
    if hasattr(logger_obj, 'log_event'):
        logger_obj.log_event('portal_fingerprint', 'INFO', {
            'message': 'Portal fingerprint recorded',
            'hash': dom_hash,
            'region': region,
            'snippet': snippet
        })
    
    return dom_hash
