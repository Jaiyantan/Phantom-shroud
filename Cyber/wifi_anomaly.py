import time
import hashlib

class WiFiAnomalyDetector:
    def __init__(self, logger):
        self.events = []  # list of dicts with 'ssid', 'bssid_hash', 'signal', 'timestamp', 'event'
        self.window_seconds = 3600  # Only keep last hour for live scanning
        self.logger = logger

    def observe(self, ssid, bssid, signal):
        now = time.time()
        bssid_hash = hashlib.sha256(bssid.encode()).hexdigest()
        entry = {
            'ssid': ssid,
            'bssid_hash': bssid_hash,
            'signal': signal,
            'timestamp': now
        }
        self.events.append(entry)
        self.trim_old(now)
        self.check_anomaly(entry)

    def trim_old(self, now):
        self.events = [e for e in self.events if now - e['timestamp'] < self.window_seconds]

    def check_anomaly(self, entry):
        # Look for same SSID, sudden BSSID changes or far signal swings
        related = [e for e in self.events if e['ssid'] == entry['ssid'] and e['bssid_hash'] != entry['bssid_hash']]
        # If a given SSID shows up with many different BSSID hashes in short time: suspicious
        if len(set(e['bssid_hash'] for e in related)) > 2:
            self.logger.log_event(
                "wifi_anomaly",
                "WARNING",
                {
                    "message": f"Multiple BSSIDs ({len(set(e['bssid_hash'] for e in related))}) seen for SSID '{entry['ssid']}' in last hour - possible Evil Twin or AP spoofing.",
                    "ssid": entry['ssid'],
                    "bssid_count": len(set(e['bssid_hash'] for e in related)),
                    "window_seconds": self.window_seconds
                }
            )
        # Check for unusual signal strength changes per SSID/BSSID
        signals = [e['signal'] for e in self.events if e['ssid'] == entry['ssid'] and e['bssid_hash'] == entry['bssid_hash']]
        if len(signals) >= 2:
            delta = max(signals) - min(signals)
            if delta > 40:
                self.logger.log_event(
                    "wifi_anomaly",
                    "WARNING",
                    {
                        "message": f"Large signal swing ({delta} dBm) seen for SSID '{entry['ssid']}'. Possible AP or MITM movement.",
                        "ssid": entry['ssid'],
                        "bssid_hash": entry['bssid_hash'],
                        "signal_range": delta,
                        "signal_values": signals[-5:]
                    }
                )
