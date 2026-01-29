"""
Debug routes for VulnAPI-101
VULNERABILITIES:
- API8:2023 - Security Misconfiguration
- API9:2023 - Improper Inventory Management
"""

import os
import sys
import traceback
from flask import Blueprint, request, jsonify, current_app

debug_bp = Blueprint('debug', __name__, url_prefix='/api/debug')


@debug_bp.route('/error', methods=['GET', 'POST'])
def trigger_error():
    """
    Endpoint to trigger errors for testing
    VULNERABILITY: API8:2023 - Verbose error messages
    """
    error_type = request.args.get('type', 'generic')

    try:
        if error_type == 'division':
            result = 1 / 0
        elif error_type == 'attribute':
            obj = None
            obj.something()
        elif error_type == 'index':
            lst = []
            item = lst[10]
        elif error_type == 'key':
            d = {}
            value = d['nonexistent']
        else:
            raise Exception('Generic test error')
    except Exception as e:
        # VULNERABILITY: Returns full stack trace
        return jsonify({
            'error': str(e),
            'type': type(e).__name__,
            'traceback': traceback.format_exc(),  # CRITICAL: Full traceback exposed!
            'file': __file__,
            'python_path': sys.path
        }), 500


@debug_bp.route('/env', methods=['GET'])
def get_environment():
    """
    Get environment variables
    VULNERABILITY: API8:2023 - Exposes sensitive environment info
    """
    # VULNERABILITY: No authentication required
    # VULNERABILITY: Exposes all environment variables
    return jsonify({
        'environment': dict(os.environ),
        'python_version': sys.version,
        'python_path': sys.path,
        'cwd': os.getcwd(),
        'user': os.getenv('USER', 'unknown'),
        'home': os.getenv('HOME', 'unknown')
    }), 200


@debug_bp.route('/config', methods=['GET'])
def get_full_config():
    """
    Get full Flask configuration
    VULNERABILITY: API8:2023 - Exposes sensitive configuration
    """
    # VULNERABILITY: No authentication
    # VULNERABILITY: Exposes all config including secrets
    config_dict = {}
    for key in current_app.config:
        value = current_app.config[key]
        # Try to make it JSON serializable
        try:
            import json
            json.dumps(value)
            config_dict[key] = value
        except (TypeError, ValueError):
            config_dict[key] = str(value)

    return jsonify({'config': config_dict}), 200


@debug_bp.route('/routes', methods=['GET'])
def get_all_routes():
    """
    List all registered routes
    VULNERABILITY: API9:2023 - Exposes API inventory
    """
    # VULNERABILITY: Exposes all routes including hidden ones
    routes = []
    for rule in current_app.url_map.iter_rules():
        routes.append({
            'endpoint': rule.endpoint,
            'methods': list(rule.methods - {'HEAD', 'OPTIONS'}),
            'path': str(rule),
            'arguments': list(rule.arguments)
        })

    return jsonify({
        'routes': sorted(routes, key=lambda x: x['path']),
        'total': len(routes)
    }), 200


@debug_bp.route('/execute', methods=['POST'])
def execute_code():
    """
    Execute arbitrary Python code
    VULNERABILITY: API8:2023 - Code execution (CRITICAL!)
    """
    # CRITICAL VULNERABILITY: Remote code execution
    data = request.get_json()
    code = data.get('code')

    if not code:
        return jsonify({'error': 'No code provided'}), 400

    try:
        # CRITICAL: Executes arbitrary Python code!
        # This is intentionally vulnerable for demonstration
        local_vars = {}
        exec(code, {'__builtins__': __builtins__}, local_vars)

        return jsonify({
            'success': True,
            'result': str(local_vars.get('result', 'No result variable set')),
            'locals': {k: str(v) for k, v in local_vars.items()}
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 400


@debug_bp.route('/eval', methods=['POST'])
def evaluate_expression():
    """
    Evaluate a Python expression
    VULNERABILITY: API8:2023 - Code execution
    """
    data = request.get_json()
    expression = data.get('expression')

    if not expression:
        return jsonify({'error': 'No expression provided'}), 400

    try:
        # CRITICAL: Evaluates arbitrary Python expressions
        result = eval(expression)
        return jsonify({
            'success': True,
            'expression': expression,
            'result': str(result)
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@debug_bp.route('/logs', methods=['GET'])
def get_debug_logs():
    """
    Get application logs
    VULNERABILITY: API8:2023 - Exposes sensitive log data
    """
    # VULNERABILITY: Returns sensitive log information
    # In a real app, this might contain PII, credentials, etc.
    return jsonify({
        'logs': [
            {'level': 'INFO', 'message': 'User admin logged in', 'timestamp': '2024-01-01 10:00:00'},
            {'level': 'DEBUG', 'message': 'Password check for user admin: admin123', 'timestamp': '2024-01-01 10:00:01'},
            {'level': 'WARNING', 'message': 'Failed login for user test with password test123', 'timestamp': '2024-01-01 10:00:02'},
            {'level': 'INFO', 'message': 'API Key generated: abc123xyz', 'timestamp': '2024-01-01 10:00:03'},
            {'level': 'DEBUG', 'message': 'Database connection string: sqlite:///vulnapi.db', 'timestamp': '2024-01-01 10:00:04'}
        ],
        'note': 'These are sample logs demonstrating the vulnerability'
    }), 200


@debug_bp.route('/phpinfo', methods=['GET'])
def phpinfo_equivalent():
    """
    PHP info equivalent for Python
    VULNERABILITY: API8:2023 - Information disclosure
    """
    import platform

    return jsonify({
        'python': {
            'version': sys.version,
            'version_info': list(sys.version_info),
            'executable': sys.executable,
            'path': sys.path,
            'platform': sys.platform
        },
        'os': {
            'name': os.name,
            'cwd': os.getcwd(),
            'cpu_count': os.cpu_count(),
            'environ': dict(os.environ)
        },
        'platform': {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor()
        },
        'flask': {
            'debug': current_app.debug,
            'testing': current_app.testing,
            'secret_key': current_app.secret_key[:10] + '...'  # Partial exposure
        }
    }), 200


@debug_bp.route('/test-db', methods=['GET'])
def test_database():
    """
    Test database connection
    VULNERABILITY: API8:2023 - Exposes database info
    """
    from app.models import db, User

    try:
        user_count = User.query.count()
        return jsonify({
            'status': 'connected',
            'database_uri': current_app.config.get('SQLALCHEMY_DATABASE_URI'),
            'user_count': user_count,
            'tables': [table for table in db.metadata.tables.keys()]
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


@debug_bp.route('/memory', methods=['GET'])
def memory_info():
    """
    Get memory information
    VULNERABILITY: API8:2023 - System information disclosure
    """
    import gc

    return jsonify({
        'gc_stats': gc.get_stats() if hasattr(gc, 'get_stats') else 'Not available',
        'gc_count': gc.get_count(),
        'objects': len(gc.get_objects())
    }), 200


# Hidden debug endpoints - API9 vulnerability
@debug_bp.route('/.hidden', methods=['GET'])
def hidden_endpoint():
    """
    VULNERABILITY: API9:2023 - Hidden/undocumented endpoint
    """
    return jsonify({
        'message': 'You found the hidden endpoint!',
        'secrets': {
            'admin_password': 'admin123',
            'api_key': 'secret-api-key-12345',
            'database': 'sqlite:///vulnapi.db'
        }
    }), 200


@debug_bp.route('/..%2f..%2f', methods=['GET'])
def another_hidden():
    """
    VULNERABILITY: API9:2023 - Path confusion hidden endpoint
    """
    return jsonify({'hidden': True, 'message': 'Another hidden endpoint'}), 200
