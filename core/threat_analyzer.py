"""
Threat Analyzer Module
Hours 14-16 Implementation

MVP Scope:
- Event correlation by time/IP
- Simple attack chain identification
- Threat severity scoring
- Basic incident timeline
"""

import logging
from datetime import datetime, timedelta
from collections import defaultdict
import json

logger = logging.getLogger(__name__)


class ThreatAnalyzer:
    """
    Simple threat correlation and analysis engine.
    Simplified for 24-hour MVP.
    """
    
    def __init__(self, log_file='data/threats.json'):
        """
        Initialize Threat Analyzer
        
        Args:
            log_file: Path to threats log file
        """
        self.log_file = log_file
        self.events = []
        self.incidents = {}
        self.correlation_window = timedelta(minutes=5)  # 5-minute correlation window
        logger.info("ThreatAnalyzer initialized")
    
    def add_event(self, event):
        """
        Add security event for analysis
        
        Args:
            event: Event dictionary with keys:
                   - type: Event type
                   - severity: HIGH, MEDIUM, LOW
                   - ip: Source IP
                   - timestamp: Event timestamp
                   - details: Additional details
        """
        # Add timestamp if not present
        if 'timestamp' not in event:
            event['timestamp'] = datetime.now()
        
        self.events.append(event)
        logger.info(f"Added event: {event.get('type')} from {event.get('ip')}")
        
        # Trigger correlation
        self.correlate_events()
        
        # Save to file
        self._save_to_file(event)
    
    def correlate_events(self):
        """
        Correlate events to identify attack patterns
        """
        # Group events by IP
        ip_events = defaultdict(list)
        
        # Only consider recent events
        cutoff_time = datetime.now() - timedelta(hours=1)
        recent_events = [e for e in self.events if e['timestamp'] > cutoff_time]
        
        for event in recent_events:
            ip = event.get('ip')
            if ip:
                ip_events[ip].append(event)
        
        # Identify incidents (multiple events from same IP)
        for ip, events in ip_events.items():
            if len(events) >= 3:  # Threshold: 3+ events = incident
                self.create_incident(ip, events)
    
    def create_incident(self, ip, events):
        """
        Create incident from correlated events
        
        Args:
            ip: Source IP address
            events: List of related events
        """
        # Calculate severity score
        severity_score = self._calculate_severity(events)
        
        # Build attack chain
        attack_chain = [
            {
                'type': e.get('type'),
                'timestamp': e.get('timestamp').isoformat() if isinstance(e.get('timestamp'), datetime) else e.get('timestamp'),
                'details': e.get('details', {})
            }
            for e in sorted(events, key=lambda x: x.get('timestamp', datetime.now()))
        ]
        
        incident = {
            'id': f"INC-{ip}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'ip': ip,
            'first_seen': min(e['timestamp'] for e in events).isoformat(),
            'last_seen': max(e['timestamp'] for e in events).isoformat(),
            'event_count': len(events),
            'severity_score': severity_score,
            'attack_chain': attack_chain
        }
        
        self.incidents[incident['id']] = incident
        logger.warning(f"Created incident {incident['id']} for IP {ip} (score: {severity_score})")
    
    def _calculate_severity(self, events):
        """
        Calculate overall severity score for events
        
        Args:
            events: List of events
            
        Returns:
            float: Severity score (0-100)
        """
        severity_map = {
            'HIGH': 10,
            'MEDIUM': 5,
            'LOW': 1
        }
        
        total_score = sum(severity_map.get(e.get('severity', 'LOW'), 1) for e in events)
        return min(total_score, 100)  # Cap at 100
    
    def get_incidents(self, limit=None):
        """
        Get identified incidents
        
        Args:
            limit: Maximum number of incidents to return
            
        Returns:
            list: Incident records
        """
        incidents = sorted(
            self.incidents.values(),
            key=lambda x: x['last_seen'],
            reverse=True
        )
        
        if limit:
            return incidents[:limit]
        return incidents
    
    def get_timeline(self, ip=None, hours=24):
        """
        Get event timeline for an IP or all events
        
        Args:
            ip: IP address (None for all)
            hours: Number of hours to look back
            
        Returns:
            list: Timeline of events
        """
        cutoff = datetime.now() - timedelta(hours=hours)
        
        timeline = [
            {
                'timestamp': e['timestamp'].isoformat() if isinstance(e['timestamp'], datetime) else e['timestamp'],
                'type': e.get('type'),
                'ip': e.get('ip'),
                'severity': e.get('severity')
            }
            for e in self.events
            if e['timestamp'] > cutoff and (ip is None or e.get('ip') == ip)
        ]
        
        return sorted(timeline, key=lambda x: x['timestamp'])
    
    def get_top_threats(self, limit=10):
        """
        Get top threat sources by incident count
        
        Args:
            limit: Number of threats to return
            
        Returns:
            list: Top threat IPs with counts
        """
        ip_counts = defaultdict(int)
        for incident in self.incidents.values():
            ip_counts[incident['ip']] += 1
        
        sorted_threats = sorted(
            ip_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return [
            {'ip': ip, 'incident_count': count}
            for ip, count in sorted_threats[:limit]
        ]
    
    def _save_to_file(self, event):
        """
        Save event to log file
        
        Args:
            event: Event dictionary
        """
        try:
            # Convert datetime to string
            event_copy = event.copy()
            if isinstance(event_copy.get('timestamp'), datetime):
                event_copy['timestamp'] = event_copy['timestamp'].isoformat()
            
            # Read existing logs
            logs = []
            try:
                with open(self.log_file, 'r') as f:
                    logs = json.load(f)
            except FileNotFoundError:
                pass
            
            # Append new event
            logs.append(event_copy)
            
            # Write back
            with open(self.log_file, 'w') as f:
                json.dump(logs, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save to file: {e}")
    
    def get_statistics(self):
        """
        Get analyzer statistics
        
        Returns:
            dict: Statistics
        """
        return {
            'total_events': len(self.events),
            'total_incidents': len(self.incidents),
            'unique_ips': len(set(e.get('ip') for e in self.events if e.get('ip')))
        }


if __name__ == "__main__":
    # Test code
    logging.basicConfig(level=logging.INFO)
    analyzer = ThreatAnalyzer()
    print("ThreatAnalyzer ready")
    print(f"Statistics: {analyzer.get_statistics()}")
