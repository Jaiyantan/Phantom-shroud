import platform, subprocess

def mac_randomization_check_and_enforce(iface: str, logger):
    if platform.system() != 'Linux':
        logger.log_event('mac_randomization', 'WARNING', {'message': 'MAC randomization enforcement supported only on Linux.'})
        return False
    try:
        # Query current MAC policy
        res = subprocess.run(['nmcli', 'device', 'show', iface], capture_output=True, text=True, timeout=5)
        for line in res.stdout.split('\n'):
            if 'GENERAL.HWADDR' in line or 'WIRED-PROPERTIES.CARRIER' in line:
                continue
            if 'wifi.cloned-mac-address:' in line or '802-11-wireless.cloned-mac-address:' in line:
                val = line.split(':', 1)[1].strip()
                if val == 'random':
                    logger.log_event('mac_randomization', 'INFO', {'interface': iface, 'message': 'MAC randomization is ENABLED.'})
                    return True
        # Enable it
        subprocess.run(['nmcli', 'device', 'set', iface, 'wifi.cloned-mac-address', 'random'], check=True, timeout=5)
        logger.log_event('mac_randomization', 'INFO', {'interface': iface, 'message': 'MAC randomization has been ENABLED.'})
        return True
    except Exception as e:
        logger.log_event('mac_randomization', 'ERROR', {'interface': iface, 'error': str(e)})
        return False
