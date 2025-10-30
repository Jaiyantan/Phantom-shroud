import subprocess
import platform

def launch_safe_login(page_url, logger):
    if platform.system() == 'Linux':
        try:
            proc = subprocess.Popen(['chromium-browser', '--incognito', '--no-first-run', '--disable-sync', '--disable-extensions', page_url])
            logger.log_event('sandbox_login', 'INFO', {'message': 'Fake login portal launched safely in sandbox.', 'pid': proc.pid, 'url': page_url})
            return proc.pid
        except Exception as e:
            logger.log_event('sandbox_login', 'ERROR', {'message': 'Could not open sandbox browser.', 'error': str(e)})
    else:
        logger.log_event('sandbox_login', 'WARNING', {'message': 'No full sandbox on this OS; opening in normal browser.'})
        subprocess.Popen(['open', page_url])
