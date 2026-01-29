"""
Admin routes for VulnAPI-101
VULNERABILITIES:
- API5:2023 - Broken Function Level Authorization
- API8:2023 - Security Misconfiguration
- API9:2023 - Improper Inventory Management
"""

from flask import Blueprint, request, jsonify, g, current_app
from app.models import db, User, Product, Order, AuditLog, Coupon
from app.utils import token_required, admin_required, log_action

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')


@admin_bp.route('/users', methods=['GET'])
@token_required
def admin_get_users():
    """
    Admin endpoint to get all users
    VULNERABILITY: API5:2023 - No actual admin check, only token required
    """
    # VULNERABILITY: Any authenticated user can access admin endpoint
    # The @admin_required decorator should be used but isn't
    users = User.query.all()

    return jsonify({
        'users': [user.to_dict() for user in users],
        'total': len(users)
    }), 200


@admin_bp.route('/users/<int:user_id>/role', methods=['PUT'])
@token_required
def admin_update_role(user_id):
    """
    Update user role
    VULNERABILITY: API5:2023 - No admin check, any user can change roles
    """
    # VULNERABILITY: Should use @admin_required but doesn't
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    new_role = data.get('role')

    if new_role not in ['user', 'admin', 'moderator']:
        return jsonify({'error': 'Invalid role'}), 400

    # VULNERABILITY: Any authenticated user can make themselves admin!
    user.role = new_role
    db.session.commit()

    log_action(g.current_user_id, 'role_changed', f'Changed user {user_id} role to {new_role}')

    return jsonify({
        'message': 'Role updated',
        'user': user.to_dict()
    }), 200


@admin_bp.route('/config', methods=['GET'])
@token_required
def get_config():
    """
    Get application configuration
    VULNERABILITIES:
    - API5:2023 - No admin check
    - API8:2023 - Exposes sensitive configuration
    """
    # VULNERABILITY: Exposes sensitive config including secrets
    config_data = {
        'SECRET_KEY': current_app.config.get('SECRET_KEY'),
        'JWT_SECRET': current_app.config.get('JWT_SECRET'),
        'DEBUG': current_app.config.get('DEBUG'),
        'DATABASE_URI': current_app.config.get('SQLALCHEMY_DATABASE_URI'),
        'ADMIN_USERNAME': current_app.config.get('ADMIN_USERNAME'),
        'ADMIN_PASSWORD': current_app.config.get('ADMIN_PASSWORD'),
    }

    return jsonify({'config': config_data}), 200


@admin_bp.route('/logs', methods=['GET'])
@token_required
def get_audit_logs():
    """
    Get audit logs
    VULNERABILITIES:
    - API5:2023 - No admin check
    - API3:2023 - Exposes sensitive action logs
    - API4:2023 - No pagination
    """
    # VULNERABILITY: Any authenticated user can view all audit logs
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).all()

    return jsonify({
        'logs': [log.to_dict() for log in logs],
        'total': len(logs)
    }), 200


@admin_bp.route('/database/query', methods=['POST'])
@token_required
def raw_query():
    """
    Execute raw database query
    VULNERABILITIES:
    - API5:2023 - No admin check
    - API8:2023 - Raw SQL execution (SQL Injection)
    """
    # CRITICAL VULNERABILITY: Raw SQL execution without proper authorization
    data = request.get_json()
    query = data.get('query')

    if not query:
        return jsonify({'error': 'Query required'}), 400

    try:
        # VULNERABILITY: Direct SQL execution - SQL Injection!
        result = db.session.execute(db.text(query))
        db.session.commit()

        # Try to fetch results if it's a SELECT
        try:
            rows = result.fetchall()
            columns = result.keys() if hasattr(result, 'keys') else []
            return jsonify({
                'success': True,
                'columns': list(columns),
                'rows': [list(row) for row in rows]
            }), 200
        except Exception:
            return jsonify({
                'success': True,
                'message': 'Query executed successfully',
                'rows_affected': result.rowcount
            }), 200

    except Exception as e:
        # VULNERABILITY: Detailed error message
        return jsonify({
            'success': False,
            'error': str(e),
            'query': query
        }), 400


@admin_bp.route('/users/<int:user_id>/deactivate', methods=['POST'])
@token_required
def deactivate_user(user_id):
    """
    Deactivate a user account
    VULNERABILITY: API5:2023 - No admin check
    """
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # VULNERABILITY: Any user can deactivate any account including admins
    user.is_active = False
    db.session.commit()

    return jsonify({'message': 'User deactivated'}), 200


@admin_bp.route('/coupons', methods=['POST'])
@token_required
def create_coupon():
    """
    Create a new coupon
    VULNERABILITY: API5:2023 - No admin check
    """
    # VULNERABILITY: Any authenticated user can create coupons
    data = request.get_json()

    coupon = Coupon(
        code=data.get('code'),
        discount_percent=data.get('discount_percent', 10),
        max_uses=data.get('max_uses', 100),
        is_active=data.get('is_active', True),
        is_internal=data.get('is_internal', False)
    )

    db.session.add(coupon)
    db.session.commit()

    return jsonify({
        'message': 'Coupon created',
        'coupon': coupon.to_dict()
    }), 201


@admin_bp.route('/system/info', methods=['GET'])
def system_info():
    """
    Get system information
    VULNERABILITIES:
    - API8:2023 - Exposes system information
    - API9:2023 - Undocumented endpoint
    """
    import sys
    import os

    # VULNERABILITY: No authentication required
    # VULNERABILITY: Exposes sensitive system information
    return jsonify({
        'python_version': sys.version,
        'platform': sys.platform,
        'cwd': os.getcwd(),
        'env_vars': dict(os.environ),  # CRITICAL: Exposes all environment variables!
        'flask_debug': current_app.debug,
        'database': current_app.config.get('SQLALCHEMY_DATABASE_URI')
    }), 200


@admin_bp.route('/backup', methods=['GET'])
@token_required
def database_backup():
    """
    Export database backup
    VULNERABILITIES:
    - API5:2023 - No admin check
    - API3:2023 - Exports all sensitive data
    """
    # VULNERABILITY: Any authenticated user can download full database
    backup = {
        'users': [user.to_dict() for user in User.query.all()],
        'products': [product.to_dict() for product in Product.query.all()],
        'orders': [order.to_dict() for order in Order.query.all()],
        'coupons': [coupon.to_dict() for coupon in Coupon.query.all()],
        'audit_logs': [log.to_dict() for log in AuditLog.query.all()]
    }

    return jsonify({'backup': backup}), 200


@admin_bp.route('/reset-database', methods=['POST'])
@token_required
def reset_database():
    """
    Reset the database
    VULNERABILITY: API5:2023 - Destructive action without proper auth
    """
    # CRITICAL: Any authenticated user can wipe the database!
    data = request.get_json()

    if data.get('confirm') != 'yes':
        return jsonify({'error': 'Must confirm with {"confirm": "yes"}'}), 400

    # This would be devastating in production
    # Keeping it semi-functional for demonstration
    return jsonify({
        'message': 'Database reset endpoint - disabled for safety',
        'warning': 'This endpoint exists and could be exploited!'
    }), 200


# Hidden admin endpoints - API9 vulnerability
@admin_bp.route('/hidden/users', methods=['GET'])
def hidden_users():
    """
    VULNERABILITY: API9:2023 - Undocumented/hidden endpoint
    """
    users = User.query.all()
    return jsonify({'users': [u.to_dict() for u in users]}), 200


@admin_bp.route('/hidden/debug', methods=['GET'])
def hidden_debug():
    """
    VULNERABILITY: API9:2023 - Undocumented debug endpoint
    """
    return jsonify({
        'debug': True,
        'secret_key': current_app.config.get('SECRET_KEY'),
        'jwt_secret': current_app.config.get('JWT_SECRET')
    }), 200
