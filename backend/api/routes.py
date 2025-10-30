"""
API Routes
Hours 16-18 Implementation

Defines all REST API endpoints for the dashboard
"""

from flask import Blueprint, jsonify, request
import logging

logger = logging.getLogger(__name__)

# Create blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api')


@api_bp.route('/status', methods=['GET'])
def get_status():
    """
    Get overall system status
    
    Returns:
        JSON with network, threats, and VPN status
    """
    try:
        from api.app import network_inspector, anomaly_detector, vpn_manager
        
        status = {
            'network': network_inspector.get_stats() if network_inspector else {},
            'threats': anomaly_detector.get_statistics() if anomaly_detector else {},
            'vpn': vpn_manager.get_status() if vpn_manager else {}
        }
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Status endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/threats/recent', methods=['GET'])
def get_recent_threats():
    """
    Get recent threat alerts
    
    Query params:
        limit: Number of threats to return (default: 10)
    
    Returns:
        JSON list of recent threats
    """
    try:
        from api.app import anomaly_detector
        
        limit = request.args.get('limit', 10, type=int)
        
        if anomaly_detector:
            threats = anomaly_detector.get_recent_threats(limit=limit)
            return jsonify({'threats': threats, 'count': len(threats)})
        
        return jsonify({'threats': [], 'count': 0})
        
    except Exception as e:
        logger.error(f"Recent threats endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/threats/incidents', methods=['GET'])
def get_incidents():
    """
    Get identified security incidents
    
    Query params:
        limit: Number of incidents to return (default: 10)
    
    Returns:
        JSON list of incidents
    """
    try:
        from api.app import threat_analyzer
        
        limit = request.args.get('limit', 10, type=int)
        
        if threat_analyzer:
            incidents = threat_analyzer.get_incidents(limit=limit)
            return jsonify({'incidents': incidents, 'count': len(incidents)})
        
        return jsonify({'incidents': [], 'count': 0})
        
    except Exception as e:
        logger.error(f"Incidents endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/vpn/connect', methods=['POST'])
def vpn_connect():
    """
    Connect to VPN
    
    Returns:
        JSON with connection status
    """
    try:
        from api.app import vpn_manager
        
        if vpn_manager:
            success = vpn_manager.connect()
            return jsonify({
                'success': success,
                'message': 'VPN connection initiated' if success else 'Failed to connect'
            })
        
        return jsonify({'success': False, 'message': 'VPN manager not available'}), 503
        
    except Exception as e:
        logger.error(f"VPN connect endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/vpn/disconnect', methods=['POST'])
def vpn_disconnect():
    """
    Disconnect from VPN
    
    Returns:
        JSON with disconnection status
    """
    try:
        from api.app import vpn_manager
        
        if vpn_manager:
            success = vpn_manager.disconnect()
            return jsonify({
                'success': success,
                'message': 'VPN disconnected' if success else 'Failed to disconnect'
            })
        
        return jsonify({'success': False, 'message': 'VPN manager not available'}), 503
        
    except Exception as e:
        logger.error(f"VPN disconnect endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/vpn/status', methods=['GET'])
def vpn_status():
    """
    Get VPN connection status
    
    Returns:
        JSON with VPN status
    """
    try:
        from api.app import vpn_manager
        
        if vpn_manager:
            status = vpn_manager.get_status()
            return jsonify(status)
        
        return jsonify({'connected': False, 'message': 'VPN manager not available'})
        
    except Exception as e:
        logger.error(f"VPN status endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/honeypot/logs', methods=['GET'])
def get_honeypot_logs():
    """
    Get honeypot interaction logs
    
    Query params:
        limit: Number of logs to return (default: 20)
    
    Returns:
        JSON list of honeypot interactions
    """
    try:
        from api.app import honeypot_ssh, honeypot_http
        
        limit = request.args.get('limit', 20, type=int)
        
        logs = []
        if honeypot_ssh:
            logs.extend(honeypot_ssh.get_interactions(limit=limit//2))
        if honeypot_http:
            logs.extend(honeypot_http.get_interactions(limit=limit//2))
        
        # Sort by timestamp
        logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return jsonify({'logs': logs[:limit], 'count': len(logs)})
        
    except Exception as e:
        logger.error(f"Honeypot logs endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/network/flows', methods=['GET'])
def get_network_flows():
    """
    Get top network flows
    
    Query params:
        limit: Number of flows to return (default: 10)
    
    Returns:
        JSON list of top flows
    """
    try:
        from api.app import network_inspector
        
        limit = request.args.get('limit', 10, type=int)
        
        if network_inspector:
            flows = network_inspector.get_top_flows(limit=limit)
            return jsonify({
                'flows': [
                    {
                        'src_ip': flow[0][0],
                        'dst_ip': flow[0][1],
                        'packet_count': flow[1]
                    }
                    for flow in flows
                ],
                'count': len(flows)
            })
        
        return jsonify({'flows': [], 'count': 0})
        
    except Exception as e:
        logger.error(f"Network flows endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/stats/summary', methods=['GET'])
def get_summary_stats():
    """
    Get summary statistics for dashboard
    
    Returns:
        JSON with aggregated statistics
    """
    try:
        from api.app import (network_inspector, anomaly_detector, 
                            vpn_manager, threat_analyzer,
                            honeypot_ssh, honeypot_http)
        
        summary = {
            'network': network_inspector.get_stats() if network_inspector else {},
            'detection': anomaly_detector.get_statistics() if anomaly_detector else {},
            'vpn': vpn_manager.get_status() if vpn_manager else {},
            'threats': threat_analyzer.get_statistics() if threat_analyzer else {},
            'honeypot': {
                'ssh': honeypot_ssh.get_statistics() if honeypot_ssh else {},
                'http': honeypot_http.get_statistics() if honeypot_http else {}
            }
        }
        
        return jsonify(summary)
        
    except Exception as e:
        logger.error(f"Summary stats endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


# Register blueprint (to be imported in app.py)
def register_routes(app):
    """Register API routes with Flask app"""
    app.register_blueprint(api_bp)
    logger.info("API routes registered")
