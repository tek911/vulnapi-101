"""
User routes for VulnAPI-101
VULNERABILITIES:
- API1:2023 - Broken Object Level Authorization (BOLA)
- API3:2023 - Broken Object Property Level Authorization
- API4:2023 - Unrestricted Resource Consumption
"""

from flask import Blueprint, request, jsonify, g
from app.models import db, User, Order
from app.utils import token_required, log_action

users_bp = Blueprint('users', __name__, url_prefix='/api/users')


@users_bp.route('', methods=['GET'])
def get_all_users():
    """
    Get all users
    VULNERABILITIES:
    - API1:2023 - No authentication required to list users
    - API3:2023 - Exposes sensitive data for all users
    - API4:2023 - No pagination limits
    """
    # VULNERABILITY: No authentication required
    # VULNERABILITY: No pagination - can return ALL users
    users = User.query.all()

    # VULNERABILITY: Exposes sensitive data for all users
    return jsonify({
        'users': [user.to_dict() for user in users],
        'total': len(users)
    }), 200


@users_bp.route('/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """
    Get a specific user by ID
    VULNERABILITIES:
    - API1:2023 - BOLA - Any user can access any other user's data
    - API3:2023 - Returns all sensitive fields
    """
    # VULNERABILITY: No authentication check
    # VULNERABILITY: No authorization - can view ANY user
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # VULNERABILITY: Returns all sensitive data including password, SSN, credit card
    return jsonify({'user': user.to_dict()}), 200


@users_bp.route('/<int:user_id>', methods=['PUT'])
@token_required
def update_user(user_id):
    """
    Update user profile
    VULNERABILITIES:
    - API1:2023 - BOLA - Can update ANY user's profile
    - API3:2023 - Mass assignment - Can update role, balance, etc.
    """
    # VULNERABILITY: No check if current user matches user_id
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()

    # VULNERABILITY: API3:2023 - Mass Assignment
    # Updates ANY field provided in request including sensitive ones
    if 'username' in data:
        user.username = data['username']
    if 'email' in data:
        user.email = data['email']
    if 'password' in data:
        user.password = data['password']  # Still plain text
    if 'role' in data:
        user.role = data['role']  # CRITICAL: Can escalate privileges!
    if 'balance' in data:
        user.balance = data['balance']  # CRITICAL: Can set own balance!
    if 'is_active' in data:
        user.is_active = data['is_active']
    if 'ssn' in data:
        user.ssn = data['ssn']
    if 'credit_card' in data:
        user.credit_card = data['credit_card']
    if 'internal_notes' in data:
        user.internal_notes = data['internal_notes']

    db.session.commit()

    log_action(g.current_user_id, 'user_updated', f'Updated user {user_id}')

    return jsonify({
        'message': 'User updated successfully',
        'user': user.to_dict()
    }), 200


@users_bp.route('/<int:user_id>', methods=['DELETE'])
@token_required
def delete_user(user_id):
    """
    Delete a user
    VULNERABILITIES:
    - API1:2023 - BOLA - Can delete ANY user
    - API5:2023 - No admin check required
    """
    # VULNERABILITY: No authorization check - any authenticated user can delete any user
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    db.session.delete(user)
    db.session.commit()

    log_action(g.current_user_id, 'user_deleted', f'Deleted user {user_id}')

    return jsonify({'message': 'User deleted successfully'}), 200


@users_bp.route('/<int:user_id>/orders', methods=['GET'])
def get_user_orders(user_id):
    """
    Get orders for a specific user
    VULNERABILITIES:
    - API1:2023 - BOLA - Can view ANY user's orders without auth
    - API3:2023 - Exposes internal order data
    """
    # VULNERABILITY: No authentication required
    # VULNERABILITY: No authorization - can view any user's orders
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    orders = Order.query.filter_by(user_id=user_id).all()

    return jsonify({
        'user_id': user_id,
        'orders': [order.to_dict() for order in orders]
    }), 200


@users_bp.route('/search', methods=['GET'])
def search_users():
    """
    Search users by various criteria
    VULNERABILITIES:
    - API4:2023 - No result limits
    - API3:2023 - Exposes sensitive data in search results
    - API8:2023 - SQL-like search patterns exposed
    """
    query = request.args.get('q', '')
    field = request.args.get('field', 'username')

    # VULNERABILITY: No limit on results
    # VULNERABILITY: Allows searching on any field including sensitive ones
    if field == 'username':
        users = User.query.filter(User.username.contains(query)).all()
    elif field == 'email':
        users = User.query.filter(User.email.contains(query)).all()
    elif field == 'ssn':
        # VULNERABILITY: Can search by SSN!
        users = User.query.filter(User.ssn.contains(query)).all()
    elif field == 'credit_card':
        # VULNERABILITY: Can search by credit card!
        users = User.query.filter(User.credit_card.contains(query)).all()
    else:
        users = User.query.filter(User.username.contains(query)).all()

    return jsonify({
        'results': [user.to_dict() for user in users],
        'total': len(users)
    }), 200


@users_bp.route('/me', methods=['GET'])
@token_required
def get_current_user():
    """
    Get current authenticated user
    VULNERABILITY: API3:2023 - Returns all sensitive fields
    """
    user = User.query.get(g.current_user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # VULNERABILITY: Returns sensitive data including password
    return jsonify({'user': user.to_dict()}), 200


@users_bp.route('/me/balance', methods=['POST'])
@token_required
def update_balance():
    """
    Update user balance (transfer/add funds)
    VULNERABILITIES:
    - API6:2023 - No verification for financial transactions
    - API1:2023 - Can transfer to any user
    """
    data = request.get_json()
    action = data.get('action')  # 'add' or 'transfer'
    amount = data.get('amount', 0)

    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400

    user = User.query.get(g.current_user_id)

    if action == 'add':
        # VULNERABILITY: No verification, can add unlimited funds
        user.balance += amount
        db.session.commit()
        return jsonify({
            'message': f'Added ${amount} to balance',
            'new_balance': user.balance
        }), 200

    elif action == 'transfer':
        target_user_id = data.get('target_user_id')
        if not target_user_id:
            return jsonify({'error': 'target_user_id required for transfer'}), 400

        target_user = User.query.get(target_user_id)
        if not target_user:
            return jsonify({'error': 'Target user not found'}), 404

        # VULNERABILITY: No confirmation, no 2FA, no limits
        if user.balance < amount:
            return jsonify({'error': 'Insufficient balance'}), 400

        user.balance -= amount
        target_user.balance += amount
        db.session.commit()

        log_action(user.id, 'balance_transfer', f'Transferred ${amount} to user {target_user_id}')

        return jsonify({
            'message': f'Transferred ${amount} to user {target_user_id}',
            'your_new_balance': user.balance
        }), 200

    return jsonify({'error': 'Invalid action'}), 400


@users_bp.route('/by-api-key/<api_key>', methods=['GET'])
def get_user_by_api_key(api_key):
    """
    Get user by API key
    VULNERABILITY: API9:2023 - Undocumented endpoint that exposes user data
    """
    user = User.query.filter_by(api_key=api_key).first()

    if not user:
        return jsonify({'error': 'Invalid API key'}), 404

    # VULNERABILITY: Exposes full user data including other API credentials
    return jsonify({'user': user.to_dict()}), 200
