"""
Main API Routes (legacy consolidated routes)
"""

from flask import Blueprint, jsonify, request
import logging

logger = logging.getLogger(__name__)

api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/status', methods=['GET'])
def get_status():
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

# Keeping a minimal subset; the full legacy endpoints remain in routes.py if needed.

def register_routes(app):
    app.register_blueprint(api_bp)
    logger.info("Main API routes registered")
