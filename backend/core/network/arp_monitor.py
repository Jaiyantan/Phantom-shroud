"""
ARP Monitor Module
Detects gratuitous ARP packets which may indicate ARP spoofing attacks.

Original Author: Joseph
Integrated into Phantom-shroud: October 31, 2025
"""

import threading
import time
import platform
import logging
from typing import Optional, Callable

try:
    from scapy.all import sniff, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)


class ARPMonitor:
    """
    Monitors network for gratuitous ARP packets.
    Gratuitous ARP is often used in MITM attacks for ARP poisoning.
    """
    
    def __init__(self, callback: Optional[Callable] = None):
        """
        Initialize ARP Monitor
        
        Args:
            callback: Function to call when gratuitous ARP detected.
                     Signature: callback(sender_ip: str, sender_mac: str, details: dict)
        """
        self.callback = callback
        self.running = False
        self._monitor_thread = None
        self._detected_arps = []
        self._lock = threading.Lock()
        
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available - ARP monitoring disabled")
        
        if platform.system() not in ['Linux', 'Darwin']:
            logger.warning(f"ARP monitoring may not work reliably on {platform.system()}")
    
    def start(self):
        """Start ARP monitoring in background thread"""
        if not SCAPY_AVAILABLE:
            logger.error("Cannot start ARP monitor: Scapy not available")
            return False
        
        if self.running:
            logger.warning("ARP monitor already running")
            return False
        
        self.running = True
        self._monitor_thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True,
            name="ARP-Monitor"
        )
        self._monitor_thread.start()
        logger.info("ARP monitor started")
        return True
    
    def stop(self):
        """Stop ARP monitoring"""
        if not self.running:
            return
        
        self.running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=3)
        logger.info("ARP monitor stopped")
    
    def _sniff_loop(self):
        """Main packet sniffing loop"""
        try:
            sniff(
                filter='arp',
                prn=self._handle_arp,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            logger.error("ARP monitor requires root/admin privileges")
        except Exception as e:
            logger.error(f"ARP monitor error: {e}")
    
    def _handle_arp(self, pkt):
        """Handle individual ARP packet"""
        try:
            if not pkt.haslayer(ARP):
                return
            
            arp = pkt[ARP]
            
            # Gratuitous ARP: sender and target IP are the same
            if arp.psrc == arp.pdst:
                details = {
                    'sender_ip': arp.psrc,
                    'sender_mac': arp.hwsrc,
                    'target_ip': arp.pdst,
                    'op': arp.op,  # 1=request, 2=reply
                    'timestamp': time.time()
                }
                
                # Store detection
                with self._lock:
                    self._detected_arps.append(details)
                    # Keep only last 100 detections
                    if len(self._detected_arps) > 100:
                        self._detected_arps = self._detected_arps[-100:]
                
                logger.warning(
                    f"Gratuitous ARP detected: {arp.psrc} ({arp.hwsrc})"
                )
                
                # Call callback if registered
                if self.callback:
                    try:
                        self.callback(arp.psrc, arp.hwsrc, details)
                    except Exception as e:
                        logger.error(f"ARP callback error: {e}")
        
        except Exception as e:
            logger.debug(f"Error handling ARP packet: {e}")
    
    def get_detections(self, limit: int = 50) -> list:
        """
        Get recent gratuitous ARP detections
        
        Args:
            limit: Maximum number of detections to return
        
        Returns:
            List of detection dictionaries
        """
        with self._lock:
            return self._detected_arps[-limit:]
    
    def clear_detections(self):
        """Clear detection history"""
        with self._lock:
            self._detected_arps = []
        logger.info("ARP detection history cleared")


# Backward compatibility with Joseph's original interface
_monitor_instance = None

def start_gratuitous_arp_monitor(logger_obj):
    """Legacy interface for compatibility"""
    global _monitor_instance
    
    def callback(sender_ip, sender_mac, details):
        if hasattr(logger_obj, 'log_event'):
            logger_obj.log_event('gratuitous_arp', 'WARNING', {
                'message': 'Gratuitous ARP detected',
                'sender_ip': sender_ip,
                'sender_mac': sender_mac
            })
    
    _monitor_instance = ARPMonitor(callback=callback)
    return _monitor_instance.start()

def stop_gratuitous_arp_monitor():
    """Legacy interface for compatibility"""
    global _monitor_instance
    if _monitor_instance:
        _monitor_instance.stop()
