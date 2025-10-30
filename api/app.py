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
    """Initialize all security modules"""
    global network_inspector, dpi_engine, anomaly_detector
    global vpn_manager, honeypot_ssh, honeypot_http, threat_analyzer
    
    try:
        logger.info("Initializing security modules...")
        
        network_inspector = NetworkInspector()
        dpi_engine = DPIEngine()
        anomaly_detector = AnomalyDetector()
        vpn_manager = VPNManager()
        threat_analyzer = ThreatAnalyzer()
        
        # Initialize honeypots on alternate ports (avoid conflicts)
        honeypot_ssh = Honeypot(port=2222, service='SSH')
        honeypot_http = Honeypot(port=8080, service='HTTP')
        
        logger.info("All modules initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize modules: {e}")


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Phantom-shroud API',
        'version': '0.1.0'
    })


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
        debug=True,
        allow_unsafe_werkzeug=True
    )
