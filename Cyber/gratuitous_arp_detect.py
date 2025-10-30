import threading
import time
import platform
from scapy.all import sniff, ARP

_monitor_thread = None
_running = False

def start_gratuitous_arp_monitor(logger):
    global _monitor_thread, _running
    if platform.system() != 'Linux':
        logger.log_event('gratuitous_arp', 'WARNING', {'message': 'Gratuitous ARP detect only supported on Linux'})
        return
    _running = True
    _monitor_thread = threading.Thread(target=_sniff_loop, args=(logger,), daemon=True)
    _monitor_thread.start()
    logger.log_event('gratuitous_arp', 'INFO', {'message': 'Gratuitous ARP monitoring started'})

def stop_gratuitous_arp_monitor():
    global _running, _monitor_thread
    _running = False
    if _monitor_thread:
        _monitor_thread.join(timeout=2)

def _sniff_loop(logger):
    try:
        sniff(filter='arp', prn=lambda pkt: _handle_arp(pkt, logger), store=0, stop_filter=lambda x: not _running)
    except Exception as e:
        logger.log_event('gratuitous_arp', 'ERROR', {'message': 'Sniff loop error', 'error': str(e)})

def _handle_arp(pkt, logger):
    if not pkt.haslayer(ARP):
        return
    arp = pkt[ARP]
    # Gratuitous ARP: sender and target IP are the same
    if arp.psrc == arp.pdst:
        logger.log_event('gratuitous_arp', 'WARNING', {
            'message': 'Gratuitous ARP detected',
            'sender_ip': arp.psrc,
            'sender_mac': arp.hwsrc
        })
