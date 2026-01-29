"""
Authentication routes for VulnAPI-101
VULNERABILITIES:
- API2:2023 - Broken Authentication (multiple issues)
- API4:2023 - Unrestricted Resource Consumption (no rate limiting)
- API8:2023 - Security Misconfiguration (verbose errors)
"""

from flask import Blueprint, request, jsonify
from app.models import db, User
from app.utils import (
    generate_token, verify_token, weak_password_hash,
    generate_api_key, generate_reset_token, log_action
)

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user
    VULNERABILITIES:
    - API2:2023 - No password complexity requirements
    - API3:2023 - Mass assignment vulnerability (can set role, balance, etc.)
    - API4:2023 - No rate limiting
    """
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'error': 'Username, email and password are required'}), 400

    # Check if user exists
    if User.query.filter_by(username=username).first():
        # VULNERABILITY: User enumeration
        return jsonify({'error': 'Username already exists'}), 400

    if User.query.filter_by(email=email).first():
        # VULNERABILITY: User enumeration
        return jsonify({'error': 'Email already registered'}), 400

    # VULNERABILITY: API3:2023 - Mass Assignment
    # Accepts any field from request, including role, balance, is_active
    new_user = User(
        username=data.get('username'),
        email=data.get('email'),
        password=data.get('password'),  # VULNERABILITY: Plain text password storage
        role=data.get('role', 'user'),  # VULNERABILITY: Can set own role!
        balance=data.get('balance', 100.0),  # VULNERABILITY: Can set own balance!
        is_active=data.get('is_active', True),
        ssn=data.get('ssn'),
        credit_card=data.get('credit_card'),
        api_key=generate_api_key()
    )

    db.session.add(new_user)
    db.session.commit()

    log_action(new_user.id, 'user_registered', f'User {username} registered')

    # VULNERABILITY: Returns sensitive data including API key
    return jsonify({
        'message': 'User registered successfully',
        'user': new_user.to_dict()
    }), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Login endpoint
    VULNERABILITIES:
    - API2:2023 - No rate limiting, no account lockout
    - API4:2023 - Unrestricted login attempts
    - API8:2023 - Verbose error messages
    """
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    user = User.query.filter_by(username=username).first()

    if not user:
        # VULNERABILITY: User enumeration - different error for non-existent user
        return jsonify({'error': 'User not found'}), 404

    # VULNERABILITY: Plain text password comparison
    if user.password != password:
        # VULNERABILITY: Verbose error - confirms user exists
        return jsonify({'error': 'Invalid password for user ' + username}), 401

    if not user.is_active:
        return jsonify({'error': 'Account is deactivated'}), 403

    token = generate_token(user.id, user.role)

    log_action(user.id, 'user_login', f'User {username} logged in')

    # VULNERABILITY: Exposes sensitive user data on login
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': user.to_dict()
    }), 200


@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    """
    Password reset request
    VULNERABILITIES:
    - API2:2023 - Weak reset token (6 digits, brute-forceable)
    - API4:2023 - No rate limiting on reset requests
    """
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        # VULNERABILITY: User enumeration
        return jsonify({'error': 'No account found with that email'}), 404

    # VULNERABILITY: Weak reset token
    reset_token = generate_reset_token()
    user.reset_token = reset_token
    db.session.commit()

    log_action(user.id, 'password_reset_requested', f'Reset token generated for {email}')

    # VULNERABILITY: Returns token in response (should be sent via email)
    return jsonify({
        'message': 'Password reset token generated',
        'reset_token': reset_token,  # CRITICAL: Should never expose this!
        'hint': 'In production, this would be sent via email'
    }), 200


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """
    Reset password with token
    VULNERABILITIES:
    - API2:2023 - No token expiration check
    - API4:2023 - No rate limiting (brute force possible)
    """
    data = request.get_json()
    email = data.get('email')
    reset_token = data.get('reset_token')
    new_password = data.get('new_password')

    if not email or not reset_token or not new_password:
        return jsonify({'error': 'Email, reset_token, and new_password are required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # VULNERABILITY: No token expiration, no attempt limiting
    if user.reset_token != reset_token:
        return jsonify({'error': 'Invalid reset token'}), 400

    # VULNERABILITY: No password complexity requirements
    user.password = new_password  # Still plain text!
    user.reset_token = None
    db.session.commit()

    log_action(user.id, 'password_reset', f'Password reset for {email}')

    return jsonify({'message': 'Password reset successful'}), 200


@auth_bp.route('/verify-token', methods=['GET'])
def verify_token_endpoint():
    """
    Verify if a token is valid
    VULNERABILITY: API9:2023 - Undocumented endpoint
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')

    if not token:
        token = request.args.get('token')

    if not token:
        return jsonify({'error': 'No token provided'}), 400

    payload = verify_token(token)

    if payload:
        return jsonify({
            'valid': True,
            'payload': payload  # VULNERABILITY: Exposes token payload
        }), 200
    else:
        return jsonify({'valid': False}), 401


@auth_bp.route('/api-key', methods=['POST'])
def regenerate_api_key():
    """
    Regenerate API key
    VULNERABILITY: API2:2023 - Only requires password, no 2FA
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    user = User.query.filter_by(username=username).first()

    if not user or user.password != password:
        return jsonify({'error': 'Invalid credentials'}), 401

    user.api_key = generate_api_key()
    db.session.commit()

    return jsonify({
        'message': 'API key regenerated',
        'api_key': user.api_key
    }), 200
