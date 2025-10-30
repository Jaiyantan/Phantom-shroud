import platform, subprocess, os

STATE_FILE = '/tmp/privacy_guard_iface_isolated.flag'

def isolate_interface(iface, logger):
    if platform.system() != 'Linux':
        logger.log_event('interface_isolator', 'WARNING', {'message': 'Interface isolation on alert only supported on Linux.'})
        return False
    try:
        subprocess.run(['nmcli', 'device', 'disconnect', iface], check=True)
        # Also bring down for extra safety
        subprocess.run(['ip', 'link', 'set', iface, 'down'], check=True)
        with open(STATE_FILE, 'w') as f:
            f.write(iface)
        logger.log_event('interface_isolator', 'CRITICAL', {
            'interface': iface,
            'message': 'Wi-Fi has been isolated due to severe MITM/ARP attack. User action required to restore.'
        })
        return True
    except Exception as e:
        logger.log_event('interface_isolator', 'ERROR', {'interface': iface, 'error': str(e)})
        return False

def restore_interface(iface, logger):
    if platform.system() != 'Linux':
        return False
    try:
        subprocess.run(['ip', 'link', 'set', iface, 'up'], check=True)
        subprocess.run(['nmcli', 'device', 'connect', iface], check=True)
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)
        logger.log_event('interface_isolator', 'INFO', {'interface': iface, 'message': 'Wi-Fi has been re-enabled.'})
        return True
    except Exception as e:
        logger.log_event('interface_isolator', 'ERROR', {'interface': iface, 'error': str(e)})
        return False
