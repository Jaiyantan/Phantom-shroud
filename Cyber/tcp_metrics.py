import threading
import time
import platform
from scapy.all import sniff, IP, TCP

gateway_ip_cache = None
def get_gateway_ip():
    global gateway_ip_cache
    if gateway_ip_cache:
        return gateway_ip_cache
    if platform.system() == 'Linux':
        import subprocess
        try:
            result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], capture_output=True, text=True, timeout=5)
            for word in result.stdout.split():
                if word.count('.') == 3:
                    gateway_ip_cache = word
                    return word
        except Exception:
            return None
    return None

class TCPMetricsMonitor:
    def __init__(self, logger):
        self.running = False
        self.thread = None
        self.gateway_ip = get_gateway_ip()
        self.seen = {}  # {src_ip: {'ttl': [], 'window': []}}
        self.logger = logger

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self.sniff_loop, daemon=True)
        self.thread.start()
        self.logger.log_event('tcp_metrics', 'INFO', {'message': 'TCP metrics monitor started.', 'gateway': self.gateway_ip})

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=3)
    
    def sniff_loop(self):
        if not self.gateway_ip:
            self.logger.log_event('tcp_metrics', 'ERROR', {'message': 'No gateway IP detected, TCP monitor not started.'})
            return
        try:
            sniff(filter=f'tcp and host {self.gateway_ip}', prn=self.handle_packet, store=0, stop_filter=lambda x: not self.running)
        except Exception as e:
            self.logger.log_event('tcp_metrics', 'ERROR', {'message': 'Sniff loop error', 'error': str(e)})

    def handle_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return
        ip = pkt[IP]
        tcp = pkt[TCP]
        src = ip.src
        ttl = ip.ttl
        window = tcp.window
        if src not in self.seen:
            self.seen[src] = {'ttls': [], 'windows': []}
        self.seen[src]['ttls'].append(ttl)
        self.seen[src]['windows'].append(window)
        if len(self.seen[src]['ttls']) > 10:
            ttls = self.seen[src]['ttls'][-10:]
            win = self.seen[src]['windows'][-10:]
            if max(ttls) - min(ttls) > 10:
                self.logger.log_event('tcp_metrics', 'WARNING', {'src': src, 'ttl_variance': max(ttls)-min(ttls), 'message': 'Significant TTL drift detected in TCP from this source.'})
            if max(win) - min(win) > 8000:
                self.logger.log_event('tcp_metrics', 'WARNING', {'src': src, 'window_variance': max(win)-min(win), 'message': 'TCP window size drift detected for this source.'})
