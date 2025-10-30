import platform, subprocess

def set_static_arp(gateway_ip, mac, logger):
    if platform.system() != 'Linux':
        logger.log_event('arp_static', 'WARNING', {'message': 'Static ARP enforcement only supported on Linux.'})
        return False
    try:
        subprocess.run(['ip', 'neigh', 'replace', gateway_ip, 'lladdr', mac, 'nud', 'permanent', 'dev', get_default_iface()], check=True)
        logger.log_event('arp_static', 'INFO', {'gateway_ip': gateway_ip, 'mac': mac, 'message': 'Static ARP entry written.'})
        return True
    except Exception as e:
        logger.log_event('arp_static', 'ERROR', {'gateway_ip': gateway_ip, 'mac': mac, 'error': str(e)})
        return False

def clear_static_arp(gateway_ip, logger):
    if platform.system() != 'Linux':
        return False
    try:
        subprocess.run(['ip', 'neigh', 'del', gateway_ip, 'dev', get_default_iface()], check=True)
        logger.log_event('arp_static', 'INFO', {'gateway_ip': gateway_ip, 'message': 'Static ARP entry removed.'})
        return True
    except Exception as e:
        logger.log_event('arp_static', 'ERROR', {'gateway_ip': gateway_ip, 'error': str(e)})
        return False

def get_default_iface():
    # Use ip route get 8.8.8.8 to find default iface
    result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], capture_output=True, text=True, timeout=5)
    for word in result.stdout.split():
        if word == 'dev':
            return result.stdout.split()[result.stdout.split().index(word)+1]
    return None
