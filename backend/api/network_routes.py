"""
Network Inspection API Routes (moved to avoid package/module name conflict)
"""

from flask import Blueprint, jsonify, request
import logging

logger = logging.getLogger(__name__)

network_bp = Blueprint('network', __name__, url_prefix='/api/network')

@network_bp.route('/status', methods=['GET'])
def get_network_status():
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
    try:
        from api.app import network_inspector
        if not network_inspector:
            return jsonify({'error': 'Network inspector not initialized'}), 503
        limit = request.args.get('limit', default=50, type=int)
        flows = network_inspector.get_active_flows(limit=limit)
        return jsonify({'flows': flows, 'count': len(flows)})
    except Exception as e:
        logger.error(f"Get flows endpoint error: {e}")
        return jsonify({'error': str(e)}), 500

@network_bp.route('/flows/top', methods=['GET'])
def get_top_talkers():
    try:
        from api.app import network_inspector
        if not network_inspector:
            return jsonify({'error': 'Network inspector not initialized'}), 503
        limit = request.args.get('limit', default=10, type=int)
        by = request.args.get('by', default='bytes', type=str)
        top_flows = network_inspector.get_top_talkers(limit=limit, by=by)
        return jsonify({'top_flows': top_flows, 'count': len(top_flows), 'sorted_by': by})
    except Exception as e:
        logger.error(f"Get top talkers endpoint error: {e}")
        return jsonify({'error': str(e)}), 500

@network_bp.route('/flows/ip/<ip_address>', methods=['GET'])
def get_flows_by_ip(ip_address):
    try:
        from api.app import network_inspector
        if not network_inspector:
            return jsonify({'error': 'Network inspector not initialized'}), 503
        flows = network_inspector.get_flows_by_ip(ip_address)
        return jsonify({'ip_address': ip_address, 'flows': flows, 'count': len(flows)})
    except Exception as e:
        logger.error(f"Get flows by IP endpoint error: {e}")
        return jsonify({'error': str(e)}), 500

@network_bp.route('/protocols', methods=['GET'])
def get_protocol_distribution():
    try:
        from api.app import network_inspector
        if not network_inspector:
            return jsonify({'error': 'Network inspector not initialized'}), 503
        distribution = network_inspector.get_protocol_distribution()
        total = sum(distribution.values())
        percentages = {}
        if total > 0:
            percentages = {protocol: round((count / total) * 100, 2) for protocol, count in distribution.items()}
        return jsonify({'distribution': distribution, 'percentages': percentages, 'total_flows': total})
    except Exception as e:
        logger.error(f"Get protocol distribution endpoint error: {e}")
        return jsonify({'error': str(e)}), 500

@network_bp.route('/interfaces', methods=['GET'])
def get_interfaces():
    try:
        from api.app import network_inspector
        if not network_inspector:
            return jsonify({'error': 'Network inspector not initialized'}), 503
        interfaces = network_inspector.get_interfaces()
        return jsonify({'interfaces': interfaces, 'count': len(interfaces)})
    except Exception as e:
        logger.error(f"Get interfaces endpoint error: {e}")
        return jsonify({'error': str(e)}), 500

@network_bp.route('/interfaces/<iface_name>', methods=['GET'])
def get_interface_info(iface_name):
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
    try:
        from api.app import network_inspector
        if not network_inspector:
            return jsonify({'error': 'Network inspector not initialized'}), 503
        data = request.get_json()
        if not data or 'filter' not in data:
            return jsonify({'error': 'Filter string required'}), 400
        bpf_filter = data['filter']
        network_inspector.set_capture_filter(bpf_filter)
        return jsonify({'message': 'Capture filter set successfully', 'filter': bpf_filter})
    except Exception as e:
        logger.error(f"Set filter endpoint error: {e}")
        return jsonify({'error': str(e)}), 500
