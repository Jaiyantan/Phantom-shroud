"""
TCP Metrics Monitor
Monitors TCP traffic for anomalies in TTL and window sizes that may indicate MITM attacks.

Original Author: Joseph
Integrated into Phantom-shroud: October 31, 2025
"""

import threading
import time
import platform
import logging
import subprocess
from typing import Optional, Callable, Dict, List
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)


class TCPMetricsMonitor:
    """
    Monitors TCP packets for suspicious variations in TTL and window sizes.
    These variations can indicate:
    - MITM proxies
    - Network path changes
    - Load balancer issues
    - Potential attack vectors
    """
    
    def __init__(self, callback: Optional[Callable] = None):
        """
        Initialize TCP Metrics Monitor
        
        Args:
            callback: Function to call on anomaly detection.
                     Signature: callback(src_ip: str, metric: str, details: dict)
        """
        self.callback = callback
        self.running = False
        self._monitor_thread = None
        self.gateway_ip = None
        
        # Track metrics per source IP
        self.metrics = defaultdict(lambda: {
            'ttls': [],
            'windows': [],
            'first_seen': None,
            'last_seen': None,
            'packet_count': 0
        })
        self._lock = threading.Lock()
        
        # Detection thresholds
        self.ttl_variance_threshold = 10
        self.window_variance_threshold = 8000
        self.sample_size = 10  # Number of packets to analyze
        
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available - TCP monitoring disabled")
    
    def start(self):
        """Start TCP metrics monitoring"""
        if not SCAPY_AVAILABLE:
            logger.error("Cannot start TCP monitor: Scapy not available")
            return False
        
        if self.running:
            logger.warning("TCP monitor already running")
            return False
        
        # Detect gateway IP
        self.gateway_ip = self._get_gateway_ip()
        if not self.gateway_ip:
            logger.warning("Could not detect gateway IP - monitoring all TCP traffic")
        else:
            logger.info(f"Monitoring TCP traffic to/from gateway: {self.gateway_ip}")
        
        self.running = True
        self._monitor_thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True,
            name="TCP-Monitor"
        )
        self._monitor_thread.start()
        logger.info("TCP metrics monitor started")
        return True
    
    def stop(self):
        """Stop TCP metrics monitoring"""
        if not self.running:
            return
        
        self.running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=3)
        logger.info("TCP metrics monitor stopped")
    
    def _get_gateway_ip(self) -> Optional[str]:
        """Detect gateway IP address"""
        if platform.system() == 'Linux':
            try:
                result = subprocess.run(
                    ['ip', 'route', 'get', '8.8.8.8'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                # Parse output to find gateway IP
                for word in result.stdout.split():
                    if word.count('.') == 3:
                        try:
                            # Validate it's an IP
                            parts = word.split('.')
                            if all(0 <= int(p) <= 255 for p in parts):
                                return word
                        except ValueError:
                            continue
            except Exception as e:
                logger.debug(f"Gateway detection error: {e}")
        
        elif platform.system() == 'Darwin':  # macOS
            try:
                result = subprocess.run(
                    ['route', 'get', 'default'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                for line in result.stdout.split('\n'):
                    if 'gateway:' in line.lower():
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[-1]
            except Exception as e:
                logger.debug(f"Gateway detection error: {e}")
        
        return None
    
    def _sniff_loop(self):
        """Main packet sniffing loop"""
        try:
            # Build filter
            if self.gateway_ip:
                bpf_filter = f'tcp and host {self.gateway_ip}'
            else:
                bpf_filter = 'tcp'
            
            sniff(
                filter=bpf_filter,
                prn=self._handle_packet,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            logger.error("TCP monitor requires root/admin privileges")
        except Exception as e:
            logger.error(f"TCP monitor error: {e}")
    
    def _handle_packet(self, pkt):
        """Handle individual TCP packet"""
        try:
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                return
            
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]
            
            src_ip = ip_layer.src
            ttl = ip_layer.ttl
            window = tcp_layer.window
            
            # Update metrics
            with self._lock:
                metrics = self.metrics[src_ip]
                
                if metrics['first_seen'] is None:
                    metrics['first_seen'] = time.time()
                
                metrics['last_seen'] = time.time()
                metrics['packet_count'] += 1
                metrics['ttls'].append(ttl)
                metrics['windows'].append(window)
                
                # Keep only recent samples
                if len(metrics['ttls']) > self.sample_size:
                    metrics['ttls'] = metrics['ttls'][-self.sample_size:]
                    metrics['windows'] = metrics['windows'][-self.sample_size:]
                
                # Analyze if we have enough samples
                if len(metrics['ttls']) >= self.sample_size:
                    self._analyze_metrics(src_ip, metrics)
        
        except Exception as e:
            logger.debug(f"Error handling TCP packet: {e}")
    
    def _analyze_metrics(self, src_ip: str, metrics: Dict):
        """Analyze collected metrics for anomalies"""
        ttls = metrics['ttls']
        windows = metrics['windows']
        
        # TTL variance analysis
        ttl_range = max(ttls) - min(ttls)
        if ttl_range > self.ttl_variance_threshold:
            details = {
                'src_ip': src_ip,
                'metric': 'ttl_variance',
                'ttl_min': min(ttls),
                'ttl_max': max(ttls),
                'ttl_range': ttl_range,
                'threshold': self.ttl_variance_threshold,
                'message': 'Significant TTL variance detected - possible MITM proxy',
                'timestamp': time.time()
            }
            
            logger.warning(
                f"TTL variance detected from {src_ip}: range={ttl_range}"
            )
            
            if self.callback:
                try:
                    self.callback(src_ip, 'ttl_variance', details)
                except Exception as e:
                    logger.error(f"Callback error: {e}")
        
        # Window size variance analysis
        window_range = max(windows) - min(windows)
        if window_range > self.window_variance_threshold:
            details = {
                'src_ip': src_ip,
                'metric': 'window_variance',
                'window_min': min(windows),
                'window_max': max(windows),
                'window_range': window_range,
                'threshold': self.window_variance_threshold,
                'message': 'TCP window size variance detected - possible network manipulation',
                'timestamp': time.time()
            }
            
            logger.warning(
                f"Window variance detected from {src_ip}: range={window_range}"
            )
            
            if self.callback:
                try:
                    self.callback(src_ip, 'window_variance', details)
                except Exception as e:
                    logger.error(f"Callback error: {e}")
    
    def get_metrics(self, src_ip: Optional[str] = None) -> Dict:
        """
        Get collected metrics
        
        Args:
            src_ip: Specific source IP (None for all)
        
        Returns:
            Dictionary of metrics
        """
        with self._lock:
            if src_ip:
                return dict(self.metrics.get(src_ip, {}))
            return {ip: dict(data) for ip, data in self.metrics.items()}
    
    def get_suspicious_sources(self) -> List[str]:
        """Get list of sources with suspicious metrics"""
        suspicious = []
        
        with self._lock:
            for src_ip, metrics in self.metrics.items():
                ttls = metrics.get('ttls', [])
                windows = metrics.get('windows', [])
                
                if len(ttls) >= self.sample_size:
                    if (max(ttls) - min(ttls)) > self.ttl_variance_threshold:
                        suspicious.append(src_ip)
                    elif (max(windows) - min(windows)) > self.window_variance_threshold:
                        if src_ip not in suspicious:
                            suspicious.append(src_ip)
        
        return suspicious
    
    def clear_metrics(self, src_ip: Optional[str] = None):
        """Clear metrics history"""
        with self._lock:
            if src_ip:
                if src_ip in self.metrics:
                    del self.metrics[src_ip]
            else:
                self.metrics.clear()
        
        logger.info(f"TCP metrics cleared{' for ' + src_ip if src_ip else ''}")
