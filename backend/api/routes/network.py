"""
Network Inspection API Routes
Phase 1 Implementation

Provides REST API endpoints for network traffic monitoring
"""

from flask import Blueprint, jsonify, request
import logging

logger = logging.getLogger(__name__)

# Create blueprint
network_bp = Blueprint('network', __name__, url_prefix='/api/network')


@network_bp.route('/status', methods=['GET'])
def get_network_status():
    """
    Get network inspection status and statistics
    
    Returns:
        JSON with network inspection status
    """
    try:
        from api.app import network_inspector
        
        if not network_inspector:
            return jsonify({'error': 'Network inspector not initialized'}), 503
        
        stats = network_inspector.get_stats()
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Network status endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


@network_bp.route('/start', methods=['POST'])
def start_inspection():
    """
    Start network inspection
    
    Returns:
        JSON with success message
    """
    try:
        from api.app import network_inspector
        
        if not network_inspector:
            return jsonify({'error': 'Network inspector not initialized'}), 503
        
        network_inspector.start()
        return jsonify({'message': 'Network inspection started', 'status': 'running'})
        
    except Exception as e:
        logger.error(f"Start inspection endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


@network_bp.route('/stop', methods=['POST'])
def stop_inspection():
    """
    Stop network inspection
    
    Returns:
        JSON with success message
    """
    try:
        from api.app import network_inspector
        
        if not network_inspector:
            return jsonify({'error': 'Network inspector not initialized'}), 503
        
        network_inspector.stop()
        return jsonify({'message': 'Network inspection stopped', 'status': 'stopped'})
        
    except Exception as e:
        logger.error(f"Stop inspection endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


@network_bp.route('/flows', methods=['GET'])
def get_flows():
    """
    Get active network flows
    
    Query params:
        limit: Maximum number of flows to return (default: 50)
    
    Returns:
        JSON list of active flows
    """
    try:
        from api.app import network_inspector
        
        if not network_inspector:
            return jsonify({'error': 'Network inspector not initialized'}), 503
        
        limit = request.args.get('limit', default=50, type=int)
        flows = network_inspector.get_active_flows(limit=limit)
        
        return jsonify({
            'flows': flows,
            'count': len(flows)
        })
        
    except Exception as e:
        logger.error(f"Get flows endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


@network_bp.route('/flows/top', methods=['GET'])
def get_top_talkers():
    """
    Get top talkers (most active flows)
    
    Query params:
        limit: Number of top flows to return (default: 10)
        by: Sort by 'bytes' or 'packets' (default: bytes)
    
    Returns:
        JSON list of top flows
    """
    try:
        from api.app import network_inspector
        
        if not network_inspector:
            return jsonify({'error': 'Network inspector not initialized'}), 503
        
        limit = request.args.get('limit', default=10, type=int)
        by = request.args.get('by', default='bytes', type=str)
        
        top_flows = network_inspector.get_top_talkers(limit=limit, by=by)
        
        return jsonify({
            'top_flows': top_flows,
            'count': len(top_flows),
            'sorted_by': by
        })
        
    except Exception as e:
        logger.error(f"Get top talkers endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


@network_bp.route('/flows/ip/<ip_address>', methods=['GET'])
def get_flows_by_ip(ip_address):
    """
    Get all flows involving a specific IP address
    
    Args:
        ip_address: IP address to search for
    
    Returns:
        JSON list of flows
    """
    try:
        from api.app import network_inspector
        
        if not network_inspector:
            return jsonify({'error': 'Network inspector not initialized'}), 503
        
        flows = network_inspector.get_flows_by_ip(ip_address)
        
        return jsonify({
            'ip_address': ip_address,
            'flows': flows,
            'count': len(flows)
        })
        
    except Exception as e:
        logger.error(f"Get flows by IP endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


@network_bp.route('/protocols', methods=['GET'])
def get_protocol_distribution():
    """
    Get distribution of protocols in active flows
    
    Returns:
        JSON with protocol statistics
    """
    try:
        from api.app import network_inspector
        
        if not network_inspector:
            return jsonify({'error': 'Network inspector not initialized'}), 503
        
        distribution = network_inspector.get_protocol_distribution()
        
        # Calculate percentages
        total = sum(distribution.values())
        percentages = {}
        if total > 0:
            percentages = {
                protocol: round((count / total) * 100, 2)
                for protocol, count in distribution.items()
            }
        
        return jsonify({
            'distribution': distribution,
            'percentages': percentages,
            'total_flows': total
        })
        
    except Exception as e:
        logger.error(f"Get protocol distribution endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


@network_bp.route('/interfaces', methods=['GET'])
def get_interfaces():
    """
    Get list of available network interfaces
    
    Returns:
        JSON list of interfaces
    """
    try:
        from api.app import network_inspector
        
        if not network_inspector:
            return jsonify({'error': 'Network inspector not initialized'}), 503
        
        interfaces = network_inspector.get_interfaces()
        
        return jsonify({
            'interfaces': interfaces,
            'count': len(interfaces)
        })
        
    except Exception as e:
        logger.error(f"Get interfaces endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


@network_bp.route('/interfaces/<iface_name>', methods=['GET'])
def get_interface_info(iface_name):
    """
    Get detailed information about a specific interface
    
    Args:
        iface_name: Name of the interface
    
    Returns:
        JSON with interface information
    """
    try:
        from api.app import network_inspector
        
        if not network_inspector:
            return jsonify({'error': 'Network inspector not initialized'}), 503
        
        info = network_inspector.get_interface_info(iface_name)
        
        if not info:
            return jsonify({'error': 'Interface not found'}), 404
        
        return jsonify(info)
        
    except Exception as e:
        logger.error(f"Get interface info endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


@network_bp.route('/filter', methods=['POST'])
def set_capture_filter():
    """
    Set BPF filter for packet capture
    
    Request JSON:
        {
            "filter": "tcp port 80"
        }
    
    Returns:
        JSON with success message
    """
    try:
        from api.app import network_inspector
        
        if not network_inspector:
            return jsonify({'error': 'Network inspector not initialized'}), 503
        
        data = request.get_json()
        if not data or 'filter' not in data:
            return jsonify({'error': 'Filter string required'}), 400
        
        bpf_filter = data['filter']
        network_inspector.set_capture_filter(bpf_filter)
        
        return jsonify({
            'message': 'Capture filter set successfully',
            'filter': bpf_filter
        })
        
    except Exception as e:
        logger.error(f"Set filter endpoint error: {e}")
        return jsonify({'error': str(e)}), 500
