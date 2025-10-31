"""
DPI API routes - minimal handlers to manage rules and list inspections
"""
from flask import Blueprint, jsonify, request, current_app
import logging

logger = logging.getLogger(__name__)

dpi_bp = Blueprint('dpi', __name__, url_prefix='/api/dpi')

@dpi_bp.route('/inspections', methods=['GET'])
def list_inspections():
    try:
        dpi_manager = current_app.config.get('DPI_MANAGER')
        if not dpi_manager:
            return jsonify({'error': 'DPI manager not initialized'}), 503
        limit = request.args.get('limit', default=50, type=int)
        protocol = request.args.get('protocol')
        filters = {}
        if protocol:
            filters['protocol'] = protocol
        inspections = dpi_manager.list_inspections(limit=limit, filters=filters if filters else None)
        return jsonify({'count': len(inspections), 'inspections': inspections})
    except Exception as e:
        logger.error(f"List inspections error: {e}")
        return jsonify({'error': str(e)}), 500

@dpi_bp.route('/rules', methods=['GET'])
def list_rules():
    try:
        dpi_manager = current_app.config.get('DPI_MANAGER')
        if not dpi_manager:
            return jsonify({'error': 'DPI manager not initialized'}), 503
        rules = dpi_manager.list_rules()
        return jsonify({'count': len(rules), 'rules': rules})
    except Exception as e:
        logger.error(f"List rules error: {e}")
        return jsonify({'error': str(e)}), 500

@dpi_bp.route('/rules', methods=['POST'])
def add_rule():
    try:
        dpi_manager = current_app.config.get('DPI_MANAGER')
        if not dpi_manager:
            return jsonify({'error': 'DPI manager not initialized'}), 503
        data = request.get_json() or {}
        try:
            rule = dpi_manager.add_rule(data)
        except Exception as e:
            return jsonify({'error': f'Invalid rule: {e}'}), 400
        return jsonify({'message': 'Rule added', 'rule': rule}), 201
    except Exception as e:
        logger.error(f"Add rule error: {e}")
        return jsonify({'error': str(e)}), 500

@dpi_bp.route('/rules/<rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    try:
        dpi_manager = current_app.config.get('DPI_MANAGER')
        if not dpi_manager:
            return jsonify({'error': 'DPI manager not initialized'}), 503
        dpi_manager.remove_rule(rule_id)
        return jsonify({'message': 'Rule removed', 'rule_id': rule_id})
    except KeyError:
        return jsonify({'error': 'Rule not found'}), 404
    except Exception as e:
        logger.error(f"Delete rule error: {e}")
        return jsonify({'error': str(e)}), 500
