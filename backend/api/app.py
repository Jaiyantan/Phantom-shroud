"""
Flask API Application
Hours 16-18 Implementation

MVP Scope:
- REST API with Flask
- WebSocket for real-time updates
- Simple CORS configuration
- Basic error handling
"""

from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import logging
import sys
import os

# Add parent directory to path to import core modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.network_inspector import NetworkInspector
from core.dpi_engine import DPIEngine
from core.anomaly_detector import AnomalyDetector
from core.vpn_manager import VPNManager
from core.honeypot import Honeypot
from core.threat_analyzer import ThreatAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'phantom-shroud-secret-key-change-in-production'
CORS(app)  # Enable CORS for dashboard

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize core modules
network_inspector = None
dpi_engine = None
anomaly_detector = None
vpn_manager = None
honeypot_ssh = None
honeypot_http = None
threat_analyzer = None


def initialize_modules():
    """Initialize all security modules without failing the whole stack"""
    global network_inspector, dpi_engine, anomaly_detector
    global vpn_manager, honeypot_ssh, honeypot_http, threat_analyzer

    logger.info("Initializing security modules...")

    # Initialize Network Inspector first (critical path)
    try:
        network_inspector = NetworkInspector()
        logger.info("NetworkInspector initialized")
    except Exception as e:
        logger.exception(f"Failed to initialize NetworkInspector: {e}")

    # Initialize DPI Engine (non-blocking)
    try:
        dpi_engine = DPIEngine()
        logger.info("DPIEngine initialized")
    except Exception as e:
        logger.warning(f"DPIEngine initialization skipped: {e}")

    # Initialize Anomaly Detector (non-blocking)
    try:
        anomaly_detector = AnomalyDetector()
        logger.info("AnomalyDetector initialized")
    except Exception as e:
        logger.warning(f"AnomalyDetector initialization skipped: {e}")

    # Initialize VPN Manager (non-blocking)
    try:
        vpn_manager = VPNManager()
        logger.info("VPNManager initialized")
    except Exception as e:
        logger.warning(f"VPNManager initialization skipped: {e}")

    # Initialize Threat Analyzer (non-blocking)
    try:
        threat_analyzer = ThreatAnalyzer()
        logger.info("ThreatAnalyzer initialized")
    except Exception as e:
        logger.warning(f"ThreatAnalyzer initialization skipped: {e}")

    # Initialize Honeypots (best-effort; may need elevated privileges or free ports)
    try:
        honeypot_ssh = Honeypot(port=2222, service='SSH')
        logger.info("SSH Honeypot initialized on port 2222")
    except Exception as e:
        logger.warning(f"SSH Honeypot initialization skipped: {e}")

    try:
        honeypot_http = Honeypot(port=8080, service='HTTP')
        logger.info("HTTP Honeypot initialized on port 8080")
    except Exception as e:
        logger.warning(f"HTTP Honeypot initialization skipped: {e}")

    logger.info("Module initialization complete")


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


# Register blueprints
from api.network_routes import network_bp
app.register_blueprint(network_bp)

# Optionally register legacy/main routes if needed
try:
    from api.routes.main import register_routes as register_main_routes
    register_main_routes(app)
except Exception as _e:
    logger.debug(f"Main routes not registered: {_e}")

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Phantom-shroud API',
        'version': '0.1.0'
    })


@app.route('/api/init', methods=['POST'])
def init_modules():
    """Endpoint to (re)initialize core modules at runtime"""
    try:
        initialize_modules()
        return jsonify({'message': 'Modules initialized'}), 200
    except Exception as e:
        logger.exception("Initialization failed")
        return jsonify({'error': str(e)}), 500


# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")
    emit('connected', {'message': 'Connected to Phantom-shroud'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")


@socketio.on('request_update')
def handle_update_request():
    """Handle real-time update request from client"""
    try:
        # Send current status
        if network_inspector:
            emit('network_update', network_inspector.get_stats())
        
        if threat_analyzer:
            emit('threat_update', threat_analyzer.get_statistics())
            
    except Exception as e:
        logger.error(f"Update request error: {e}")


if __name__ == '__main__':
    # Initialize modules
    initialize_modules()
    
    # Start server
    logger.info("Starting Phantom-shroud API server...")
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=True
    )
