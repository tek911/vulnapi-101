"""
Order routes for VulnAPI-101
VULNERABILITIES:
- API1:2023 - Broken Object Level Authorization (BOLA)
- API3:2023 - Broken Object Property Level Authorization
- API6:2023 - Unrestricted Access to Sensitive Business Flows
"""

from flask import Blueprint, request, jsonify, g
from app.models import db, Order, Product, User
from app.utils import token_required, log_action

orders_bp = Blueprint('orders', __name__, url_prefix='/api/orders')


@orders_bp.route('', methods=['GET'])
def get_all_orders():
    """
    Get all orders
    VULNERABILITIES:
    - API1:2023 - No authentication, can view ALL orders
    - API3:2023 - Exposes internal tracking and profit data
    - API4:2023 - No pagination
    """
    # VULNERABILITY: No authentication required
    # VULNERABILITY: No pagination limits
    orders = Order.query.all()

    # VULNERABILITY: Exposes all orders with internal data
    return jsonify({
        'orders': [order.to_dict() for order in orders],
        'total': len(orders)
    }), 200


@orders_bp.route('/<int:order_id>', methods=['GET'])
def get_order(order_id):
    """
    Get a specific order
    VULNERABILITIES:
    - API1:2023 - BOLA - Any user can view any order
    - API3:2023 - Exposes internal order data
    """
    # VULNERABILITY: No authentication or authorization check
    order = Order.query.get(order_id)

    if not order:
        return jsonify({'error': 'Order not found'}), 404

    # VULNERABILITY: Exposes internal tracking, profit margin, full shipping address
    return jsonify({'order': order.to_dict()}), 200


@orders_bp.route('', methods=['POST'])
@token_required
def create_order():
    """
    Create a new order
    VULNERABILITIES:
    - API6:2023 - No verification of business logic
    - API3:2023 - Can set internal fields
    - Price manipulation possible
    """
    data = request.get_json()

    product_id = data.get('product_id')
    quantity = data.get('quantity', 1)

    if not product_id:
        return jsonify({'error': 'product_id is required'}), 400

    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    # VULNERABILITY: Client-provided price not validated against actual price
    if 'total_price' in data:
        # CRITICAL: Trusts client-provided price!
        total_price = data['total_price']
    else:
        total_price = product.price * quantity

    # VULNERABILITY: No stock check
    # VULNERABILITY: Can set internal fields

    order = Order(
        user_id=data.get('user_id', g.current_user_id),  # VULNERABILITY: Can create order for other users
        product_id=product_id,
        quantity=quantity,
        total_price=total_price,
        status=data.get('status', 'pending'),  # VULNERABILITY: Can set own status
        shipping_address=data.get('shipping_address'),
        payment_method=data.get('payment_method'),
        card_last_four=data.get('card_last_four'),
        internal_tracking=data.get('internal_tracking'),  # Should be admin only
        profit_margin=data.get('profit_margin')  # Should be system calculated
    )

    db.session.add(order)
    db.session.commit()

    log_action(g.current_user_id, 'order_created', f'Created order {order.id}')

    return jsonify({
        'message': 'Order created successfully',
        'order': order.to_dict()
    }), 201


@orders_bp.route('/<int:order_id>', methods=['PUT'])
@token_required
def update_order(order_id):
    """
    Update an order
    VULNERABILITIES:
    - API1:2023 - BOLA - Can update any order
    - API3:2023 - Can modify any field including status
    - API6:2023 - Can change order status inappropriately
    """
    order = Order.query.get(order_id)

    if not order:
        return jsonify({'error': 'Order not found'}), 404

    # VULNERABILITY: No check if order belongs to current user
    data = request.get_json()

    # VULNERABILITY: Can modify any field
    if 'status' in data:
        order.status = data['status']  # Can change to 'delivered' without shipping!
    if 'total_price' in data:
        order.total_price = data['total_price']  # Can change price after order!
    if 'shipping_address' in data:
        order.shipping_address = data['shipping_address']
    if 'user_id' in data:
        order.user_id = data['user_id']  # Can reassign order to different user!
    if 'internal_tracking' in data:
        order.internal_tracking = data['internal_tracking']
    if 'profit_margin' in data:
        order.profit_margin = data['profit_margin']

    db.session.commit()

    log_action(g.current_user_id, 'order_updated', f'Updated order {order_id}')

    return jsonify({
        'message': 'Order updated successfully',
        'order': order.to_dict()
    }), 200


@orders_bp.route('/<int:order_id>', methods=['DELETE'])
@token_required
def delete_order(order_id):
    """
    Delete/Cancel an order
    VULNERABILITY: API1:2023 - BOLA - Can delete any order
    """
    order = Order.query.get(order_id)

    if not order:
        return jsonify({'error': 'Order not found'}), 404

    # VULNERABILITY: No ownership check
    # VULNERABILITY: No check if order can be cancelled (already shipped?)
    db.session.delete(order)
    db.session.commit()

    log_action(g.current_user_id, 'order_deleted', f'Deleted order {order_id}')

    return jsonify({'message': 'Order deleted successfully'}), 200


@orders_bp.route('/<int:order_id>/status', methods=['PATCH'])
@token_required
def update_order_status(order_id):
    """
    Update order status
    VULNERABILITIES:
    - API1:2023 - BOLA
    - API5:2023 - No role check for admin actions
    - API6:2023 - Can skip business flow steps
    """
    order = Order.query.get(order_id)

    if not order:
        return jsonify({'error': 'Order not found'}), 404

    data = request.get_json()
    new_status = data.get('status')

    # VULNERABILITY: No ownership check
    # VULNERABILITY: No state machine validation
    # Can go from 'pending' directly to 'delivered' skipping payment, shipping, etc.
    valid_statuses = ['pending', 'confirmed', 'paid', 'shipped', 'delivered', 'cancelled', 'refunded']

    if new_status not in valid_statuses:
        return jsonify({'error': 'Invalid status'}), 400

    order.status = new_status
    db.session.commit()

    return jsonify({
        'message': 'Status updated',
        'order': order.to_dict()
    }), 200


@orders_bp.route('/<int:order_id>/refund', methods=['POST'])
@token_required
def refund_order(order_id):
    """
    Request refund for an order
    VULNERABILITIES:
    - API1:2023 - BOLA - Can refund any order
    - API6:2023 - No verification, unlimited refunds
    """
    order = Order.query.get(order_id)

    if not order:
        return jsonify({'error': 'Order not found'}), 404

    # VULNERABILITY: No ownership check
    # VULNERABILITY: No check if already refunded
    # VULNERABILITY: No verification of refund reason

    user = User.query.get(order.user_id)
    if user:
        # VULNERABILITY: Can refund multiple times for same order
        user.balance += order.total_price
        order.status = 'refunded'
        db.session.commit()

        return jsonify({
            'message': 'Refund processed',
            'amount': order.total_price,
            'new_balance': user.balance
        }), 200

    return jsonify({'error': 'User not found'}), 404


@orders_bp.route('/bulk-status', methods=['POST'])
@token_required
def bulk_status_update():
    """
    Bulk update order statuses
    VULNERABILITIES:
    - API5:2023 - No admin authorization
    - API4:2023 - No limit on number of updates
    """
    data = request.get_json()
    order_ids = data.get('order_ids', [])
    new_status = data.get('status')

    if not order_ids or not new_status:
        return jsonify({'error': 'order_ids and status required'}), 400

    # VULNERABILITY: No limit on number of orders to update
    # VULNERABILITY: No authorization check
    updated = []
    for order_id in order_ids:
        order = Order.query.get(order_id)
        if order:
            order.status = new_status
            updated.append(order_id)

    db.session.commit()

    return jsonify({
        'message': 'Bulk update completed',
        'updated_orders': updated
    }), 200


@orders_bp.route('/statistics', methods=['GET'])
def get_order_statistics():
    """
    Get order statistics
    VULNERABILITIES:
    - API3:2023 - Exposes business-sensitive data
    - API9:2023 - Undocumented endpoint
    """
    # VULNERABILITY: No authentication required
    # VULNERABILITY: Exposes sensitive business metrics

    total_orders = Order.query.count()
    total_revenue = sum(o.total_price for o in Order.query.all())
    total_profit = sum(o.profit_margin or 0 for o in Order.query.all())

    # Status breakdown
    status_counts = {}
    for order in Order.query.all():
        status_counts[order.status] = status_counts.get(order.status, 0) + 1

    return jsonify({
        'total_orders': total_orders,
        'total_revenue': total_revenue,
        'total_profit': total_profit,  # VULNERABILITY: Exposes profit!
        'status_breakdown': status_counts,
        'average_order_value': total_revenue / total_orders if total_orders > 0 else 0
    }), 200
