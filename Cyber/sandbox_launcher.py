import subprocess
import sys
import platform

def open_url_sandboxed(url, logger):
    if platform.system() == 'Linux':
        try:
            proc = subprocess.Popen(['chromium-browser', '--incognito', '--no-first-run', '--disable-sync', '--disable-extensions', url])
            logger.log_event('sandbox_launcher', 'INFO', {'message': 'Opened URL in sandboxed Chromium.', 'pid': proc.pid, 'url': url})
            return proc.pid
        except Exception as e:
            logger.log_event('sandbox_launcher', 'ERROR', {'message': 'Failed to launch sandboxed browser.', 'error': str(e)})
    elif platform.system() == 'Windows':
        logger.log_event('sandbox_launcher', 'WARNING', {'message': 'Sandboxed browser launching only supported on Linux.'})
        subprocess.Popen(['start', url], shell=True)
    elif platform.system() == 'Darwin':
        logger.log_event('sandbox_launcher', 'WARNING', {'message': 'Full sandbox not supported; opening browser.'})
        subprocess.Popen(['open', '-a', 'Safari', url])
