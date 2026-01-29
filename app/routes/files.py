"""
File handling routes for VulnAPI-101
VULNERABILITIES:
- API7:2023 - Server Side Request Forgery (SSRF)
- API8:2023 - Security Misconfiguration
- API10:2023 - Unsafe Consumption of APIs
"""

import os
import requests
from flask import Blueprint, request, jsonify, g, send_file, current_app
from werkzeug.utils import secure_filename
from app.utils import token_required, fetch_url, process_external_data

files_bp = Blueprint('files', __name__, url_prefix='/api/files')

UPLOAD_FOLDER = 'uploads'


@files_bp.route('/fetch', methods=['POST'])
@token_required
def fetch_remote_file():
    """
    Fetch content from a remote URL
    VULNERABILITY: API7:2023 - Server Side Request Forgery (SSRF)
    - No URL validation
    - Can access internal resources
    - Can access cloud metadata endpoints
    """
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    # VULNERABILITY: No validation of URL
    # Can access:
    # - Internal services (http://localhost:8080/admin)
    # - Cloud metadata (http://169.254.169.254/latest/meta-data/)
    # - Internal network (http://192.168.1.1/admin)

    result = fetch_url(url)

    return jsonify({
        'url': url,
        'result': result
    }), 200


@files_bp.route('/fetch-validate', methods=['POST'])
@token_required
def fetch_with_validation():
    """
    Fetch URL with 'validation'
    VULNERABILITY: API7:2023 - SSRF with weak validation bypass
    """
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    # VULNERABILITY: Weak validation - easily bypassed
    blocked = ['localhost', '127.0.0.1', '0.0.0.0']
    url_lower = url.lower()

    for blocked_host in blocked:
        if blocked_host in url_lower:
            return jsonify({'error': 'Blocked host detected'}), 403

    # BYPASS: Can use:
    # - http://127.1/ (shorthand)
    # - http://2130706433/ (decimal IP)
    # - http://0x7f000001/ (hex IP)
    # - http://localhost.attacker.com/ (DNS rebinding)
    # - http://[::1]/ (IPv6 localhost)

    result = fetch_url(url)
    return jsonify({'result': result}), 200


@files_bp.route('/webhook', methods=['POST'])
@token_required
def register_webhook():
    """
    Register a webhook URL
    VULNERABILITY: API7:2023 - SSRF via webhook
    """
    data = request.get_json()
    webhook_url = data.get('webhook_url')
    event = data.get('event', 'order_created')

    if not webhook_url:
        return jsonify({'error': 'webhook_url required'}), 400

    # VULNERABILITY: Will call arbitrary URLs when events occur
    # Test the webhook immediately
    try:
        # VULNERABILITY: Makes request to user-controlled URL
        response = requests.post(webhook_url, json={
            'event': 'webhook_test',
            'message': 'Webhook registered successfully'
        }, timeout=5)

        return jsonify({
            'message': 'Webhook registered and tested',
            'test_status_code': response.status_code,
            'test_response': response.text[:500]
        }), 200
    except Exception as e:
        return jsonify({
            'message': 'Webhook registered but test failed',
            'error': str(e)
        }), 200


@files_bp.route('/upload', methods=['POST'])
@token_required
def upload_file():
    """
    Upload a file
    VULNERABILITIES:
    - API8:2023 - Dangerous file types allowed
    - No file size limit enforcement
    - Path traversal possible
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # VULNERABILITY: Allows dangerous extensions
    # VULNERABILITY: secure_filename can be bypassed in some cases
    filename = file.filename  # VULNERABILITY: Not using secure_filename!

    # Create upload directory if not exists
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    # VULNERABILITY: Path traversal possible with ../
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    return jsonify({
        'message': 'File uploaded successfully',
        'filename': filename,
        'path': filepath
    }), 200


@files_bp.route('/upload-safe', methods=['POST'])
@token_required
def upload_file_safe():
    """
    'Safe' file upload - still vulnerable
    VULNERABILITY: API8:2023 - Incomplete validation
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']

    # VULNERABILITY: Only checks extension, not content
    allowed_extensions = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
    filename = secure_filename(file.filename)
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

    if ext not in allowed_extensions:
        return jsonify({'error': 'File type not allowed'}), 400

    # VULNERABILITY: Can upload malicious content with allowed extension
    # e.g., PHP code in file.png.txt or polyglot files

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    return jsonify({
        'message': 'File uploaded',
        'filename': filename
    }), 200


@files_bp.route('/download/<path:filename>', methods=['GET'])
def download_file(filename):
    """
    Download a file
    VULNERABILITY: Path traversal
    """
    # VULNERABILITY: No path validation - can access any file
    # Example: /api/files/download/../../../etc/passwd
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    if os.path.exists(filepath):
        return send_file(filepath)

    return jsonify({'error': 'File not found'}), 404


@files_bp.route('/read', methods=['POST'])
@token_required
def read_file():
    """
    Read file contents
    VULNERABILITY: Path traversal
    """
    data = request.get_json()
    filename = data.get('filename')

    if not filename:
        return jsonify({'error': 'Filename required'}), 400

    # VULNERABILITY: Can read any file on the system
    # Example: {"filename": "../../../etc/passwd"}
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    try:
        with open(filepath, 'r') as f:
            content = f.read()
        return jsonify({
            'filename': filename,
            'content': content
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@files_bp.route('/import-data', methods=['POST'])
@token_required
def import_external_data():
    """
    Import data from external API
    VULNERABILITY: API10:2023 - Unsafe Consumption of APIs
    """
    data = request.get_json()
    api_url = data.get('api_url')

    if not api_url:
        return jsonify({'error': 'api_url required'}), 400

    try:
        # VULNERABILITY: Fetches and trusts external data completely
        response = requests.get(api_url, timeout=10)
        external_data = response.json()

        # VULNERABILITY: No validation of external data
        # Directly processes potentially malicious data
        processed = process_external_data(external_data)

        # VULNERABILITY: Could execute arbitrary operations based on external data
        if 'operations' in processed:
            results = []
            for op in processed['operations']:
                # Blindly executes operations from external source
                results.append({
                    'operation': op.get('type'),
                    'status': 'executed'
                })

            return jsonify({
                'message': 'Data imported and processed',
                'results': results
            }), 200

        return jsonify({
            'message': 'Data imported',
            'data': processed
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@files_bp.route('/proxy', methods=['GET', 'POST'])
@token_required
def proxy_request():
    """
    Proxy requests to external services
    VULNERABILITY: API7:2023 - SSRF - Full proxy functionality
    """
    target_url = request.args.get('url') or request.json.get('url')
    method = request.args.get('method', 'GET').upper()

    if not target_url:
        return jsonify({'error': 'URL required'}), 400

    # VULNERABILITY: Full proxy with no restrictions
    try:
        if method == 'GET':
            resp = requests.get(target_url, timeout=10)
        elif method == 'POST':
            body = request.json.get('body', {})
            resp = requests.post(target_url, json=body, timeout=10)
        else:
            resp = requests.request(method, target_url, timeout=10)

        return jsonify({
            'status_code': resp.status_code,
            'headers': dict(resp.headers),
            'body': resp.text[:10000]
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@files_bp.route('/avatar', methods=['POST'])
@token_required
def set_avatar_from_url():
    """
    Set user avatar from URL
    VULNERABILITY: API7:2023 - SSRF via image fetch
    """
    data = request.get_json()
    image_url = data.get('url')

    if not image_url:
        return jsonify({'error': 'URL required'}), 400

    # VULNERABILITY: Fetches arbitrary URL
    try:
        response = requests.get(image_url, timeout=10)

        # VULNERABILITY: No content-type validation
        # Could fetch non-image content from internal resources

        return jsonify({
            'message': 'Avatar fetched',
            'content_type': response.headers.get('content-type'),
            'size': len(response.content),
            'url': image_url
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 400
