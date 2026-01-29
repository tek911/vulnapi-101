"""
Utility functions for VulnAPI-101
Contains authentication helpers and other utilities
VULNERABILITIES: Multiple authentication and security issues
"""

import jwt
import hashlib
import secrets
import requests
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app, g
from app.models import User, AuditLog, db


def generate_token(user_id, role='user'):
    """
    Generate JWT token
    VULNERABILITY: API2:2023 - Broken Authentication
    - Weak secret key
    - Long expiration time
    - No token revocation mechanism
    """
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=current_app.config.get('JWT_EXPIRATION_HOURS', 8760)),
        'iat': datetime.utcnow()
    }
    # VULNERABILITY: Using weak secret from config
    return jwt.encode(payload, current_app.config['JWT_SECRET'], algorithm='HS256')


def verify_token(token):
    """
    Verify JWT token
    VULNERABILITY: API2:2023 - Broken Authentication
    - No token blacklist check
    - Accepts tokens even after password change
    """
    try:
        payload = jwt.decode(
            token,
            current_app.config['JWT_SECRET'],
            algorithms=['HS256']
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def token_required(f):
    """
    Decorator for routes that require authentication
    VULNERABILITY: API2:2023 - Broken Authentication
    - Token extracted from multiple sources without priority
    - No additional verification
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # VULNERABILITY: Accepts token from multiple sources
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
            else:
                token = auth_header

        # Also check query param and cookie (increases attack surface)
        if not token:
            token = request.args.get('token')
        if not token:
            token = request.cookies.get('auth_token')

        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        payload = verify_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401

        # VULNERABILITY: No check if user still exists or is active
        g.current_user_id = payload['user_id']
        g.current_user_role = payload.get('role', 'user')

        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """
    Decorator for admin-only routes
    VULNERABILITY: API5:2023 - Broken Function Level Authorization
    - Role only checked from token, not database
    - No additional verification
    """
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        # VULNERABILITY: Role from token only, not verified against DB
        if g.current_user_role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated


def weak_password_hash(password):
    """
    VULNERABILITY: API2:2023 - Broken Authentication
    - Using MD5 which is cryptographically broken
    - No salt
    """
    return hashlib.md5(password.encode()).hexdigest()


def generate_api_key():
    """Generate an API key"""
    return secrets.token_hex(32)


def generate_reset_token():
    """
    VULNERABILITY: API2:2023 - Broken Authentication
    - Predictable reset token (short, numeric only)
    """
    # Using only 6 digits - very brute-forceable
    import random
    return str(random.randint(100000, 999999))


def log_action(user_id, action, details=None):
    """Log an action to the audit log"""
    try:
        log = AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            ip_address=request.remote_addr if request else None
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        pass  # Silently fail - bad practice


def fetch_url(url):
    """
    Fetch content from URL
    VULNERABILITY: API7:2023 - Server Side Request Forgery (SSRF)
    - No URL validation
    - No protocol restriction
    - Can access internal resources
    """
    try:
        # VULNERABILITY: No validation of URL
        response = requests.get(url, timeout=10, allow_redirects=True)
        return {
            'status_code': response.status_code,
            'content': response.text[:10000],  # Limit response size
            'headers': dict(response.headers),
            'url': response.url
        }
    except requests.RequestException as e:
        return {'error': str(e)}


def validate_url(url):
    """
    URL validation - intentionally weak
    VULNERABILITY: API7:2023 - SSRF
    - Easily bypassed validation
    """
    # VULNERABILITY: Only basic check, easily bypassed
    blocked = ['localhost', '127.0.0.1']
    for blocked_host in blocked:
        if blocked_host in url.lower():
            return False
    # Can still access 0.0.0.0, internal IPs, etc.
    return True


def process_external_data(data):
    """
    Process data from external API
    VULNERABILITY: API10:2023 - Unsafe Consumption of APIs
    - No validation of external data
    - Direct use of external data in queries/operations
    """
    # VULNERABILITY: Trusting external data completely
    return data


def get_user_from_request():
    """Get current user from request context"""
    if hasattr(g, 'current_user_id'):
        return User.query.get(g.current_user_id)
    return None
