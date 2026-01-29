"""
Product routes for VulnAPI-101
VULNERABILITIES:
- API1:2023 - Broken Object Level Authorization
- API3:2023 - Broken Object Property Level Authorization
- API4:2023 - Unrestricted Resource Consumption
- API6:2023 - Unrestricted Access to Sensitive Business Flows
"""

from flask import Blueprint, request, jsonify, g
from app.models import db, Product, Comment, Coupon, User
from app.utils import token_required, log_action

products_bp = Blueprint('products', __name__, url_prefix='/api/products')


@products_bp.route('', methods=['GET'])
def get_all_products():
    """
    Get all products
    VULNERABILITIES:
    - API3:2023 - Exposes internal cost and admin notes
    - API4:2023 - No pagination limits
    """
    # VULNERABILITY: No pagination - can return thousands of products
    limit = request.args.get('limit', type=int)  # Ignored if not provided

    if limit:
        products = Product.query.limit(limit).all()
    else:
        # VULNERABILITY: No default limit
        products = Product.query.all()

    # VULNERABILITY: Exposes internal data like cost, admin notes
    return jsonify({
        'products': [product.to_dict() for product in products],
        'total': len(products)
    }), 200


@products_bp.route('/<int:product_id>', methods=['GET'])
def get_product(product_id):
    """
    Get a specific product
    VULNERABILITY: API3:2023 - Exposes internal cost and admin notes
    """
    product = Product.query.get(product_id)

    if not product:
        return jsonify({'error': 'Product not found'}), 404

    # VULNERABILITY: Exposes internal data
    return jsonify({'product': product.to_dict()}), 200


@products_bp.route('', methods=['POST'])
@token_required
def create_product():
    """
    Create a new product
    VULNERABILITIES:
    - API5:2023 - No admin check required
    - API3:2023 - Can set internal fields via mass assignment
    """
    # VULNERABILITY: Any authenticated user can create products
    data = request.get_json()

    if not data.get('name') or not data.get('price'):
        return jsonify({'error': 'Name and price are required'}), 400

    # VULNERABILITY: Mass assignment - can set internal_cost, admin_notes
    product = Product(
        name=data.get('name'),
        description=data.get('description'),
        price=data.get('price'),
        internal_cost=data.get('internal_cost'),  # Should be admin only
        stock=data.get('stock', 0),
        category=data.get('category'),
        is_active=data.get('is_active', True),
        admin_notes=data.get('admin_notes')  # Should be admin only
    )

    db.session.add(product)
    db.session.commit()

    log_action(g.current_user_id, 'product_created', f'Created product {product.id}')

    return jsonify({
        'message': 'Product created successfully',
        'product': product.to_dict()
    }), 201


@products_bp.route('/<int:product_id>', methods=['PUT'])
@token_required
def update_product(product_id):
    """
    Update a product
    VULNERABILITIES:
    - API1:2023 - Any user can update any product
    - API3:2023 - Mass assignment of internal fields
    - API5:2023 - No admin check
    """
    product = Product.query.get(product_id)

    if not product:
        return jsonify({'error': 'Product not found'}), 404

    data = request.get_json()

    # VULNERABILITY: Mass assignment
    for key in ['name', 'description', 'price', 'internal_cost', 'stock', 'category', 'is_active', 'admin_notes']:
        if key in data:
            setattr(product, key, data[key])

    db.session.commit()

    log_action(g.current_user_id, 'product_updated', f'Updated product {product_id}')

    return jsonify({
        'message': 'Product updated successfully',
        'product': product.to_dict()
    }), 200


@products_bp.route('/<int:product_id>', methods=['DELETE'])
@token_required
def delete_product(product_id):
    """
    Delete a product
    VULNERABILITY: API5:2023 - No admin authorization check
    """
    # VULNERABILITY: Any authenticated user can delete products
    product = Product.query.get(product_id)

    if not product:
        return jsonify({'error': 'Product not found'}), 404

    db.session.delete(product)
    db.session.commit()

    log_action(g.current_user_id, 'product_deleted', f'Deleted product {product_id}')

    return jsonify({'message': 'Product deleted successfully'}), 200


@products_bp.route('/<int:product_id>/comments', methods=['GET'])
def get_product_comments(product_id):
    """
    Get comments for a product
    VULNERABILITY: API4:2023 - No pagination
    """
    product = Product.query.get(product_id)

    if not product:
        return jsonify({'error': 'Product not found'}), 404

    # VULNERABILITY: No pagination limits
    comments = Comment.query.filter_by(product_id=product_id).all()

    return jsonify({
        'product_id': product_id,
        'comments': [comment.to_dict() for comment in comments]
    }), 200


@products_bp.route('/<int:product_id>/comments', methods=['POST'])
@token_required
def add_comment(product_id):
    """
    Add a comment to a product
    VULNERABILITIES:
    - API4:2023 - No rate limiting on comments
    - API6:2023 - Can spam reviews
    """
    product = Product.query.get(product_id)

    if not product:
        return jsonify({'error': 'Product not found'}), 404

    data = request.get_json()

    # VULNERABILITY: No rate limiting - can spam unlimited comments
    # VULNERABILITY: No purchase verification - can review without buying
    comment = Comment(
        user_id=g.current_user_id,
        product_id=product_id,
        content=data.get('content', ''),
        rating=data.get('rating'),
        is_approved=True  # VULNERABILITY: Auto-approved
    )

    db.session.add(comment)
    db.session.commit()

    return jsonify({
        'message': 'Comment added successfully',
        'comment': comment.to_dict()
    }), 201


@products_bp.route('/coupons', methods=['GET'])
def get_coupons():
    """
    Get available coupons
    VULNERABILITIES:
    - API3:2023 - Exposes internal coupons
    - API9:2023 - Undocumented endpoint
    """
    # VULNERABILITY: No authentication required
    # VULNERABILITY: Exposes ALL coupons including internal ones
    coupons = Coupon.query.all()

    return jsonify({
        'coupons': [coupon.to_dict() for coupon in coupons]
    }), 200


@products_bp.route('/coupons/validate', methods=['POST'])
def validate_coupon():
    """
    Validate a coupon code
    VULNERABILITY: API6:2023 - No rate limiting allows brute force
    """
    data = request.get_json()
    code = data.get('code')

    if not code:
        return jsonify({'error': 'Coupon code required'}), 400

    # VULNERABILITY: No rate limiting - can brute force coupon codes
    coupon = Coupon.query.filter_by(code=code, is_active=True).first()

    if not coupon:
        # VULNERABILITY: Timing attack possible
        return jsonify({'valid': False, 'error': 'Invalid coupon code'}), 400

    if coupon.current_uses >= coupon.max_uses:
        return jsonify({'valid': False, 'error': 'Coupon exhausted'}), 400

    return jsonify({
        'valid': True,
        'coupon': coupon.to_dict()
    }), 200


@products_bp.route('/coupons/apply', methods=['POST'])
@token_required
def apply_coupon():
    """
    Apply a coupon to user's cart/order
    VULNERABILITIES:
    - API6:2023 - No verification of coupon use per user
    - Can apply same coupon multiple times
    """
    data = request.get_json()
    code = data.get('code')
    order_total = data.get('order_total', 0)

    coupon = Coupon.query.filter_by(code=code, is_active=True).first()

    if not coupon:
        return jsonify({'error': 'Invalid coupon'}), 400

    # VULNERABILITY: No per-user tracking - same user can use unlimited times
    discount = order_total * (coupon.discount_percent / 100)

    # VULNERABILITY: Doesn't actually increment usage or track per-user use
    # coupon.current_uses += 1  # This should happen but doesn't

    return jsonify({
        'original_total': order_total,
        'discount': discount,
        'new_total': order_total - discount
    }), 200


@products_bp.route('/bulk-price-update', methods=['POST'])
@token_required
def bulk_price_update():
    """
    Bulk update product prices
    VULNERABILITIES:
    - API5:2023 - No admin check
    - API4:2023 - No limits on number of updates
    """
    # VULNERABILITY: Any authenticated user can bulk update prices
    data = request.get_json()
    updates = data.get('updates', [])

    # VULNERABILITY: No limit on number of updates
    results = []
    for update in updates:
        product_id = update.get('product_id')
        new_price = update.get('price')

        if product_id and new_price is not None:
            product = Product.query.get(product_id)
            if product:
                product.price = new_price
                results.append({'product_id': product_id, 'new_price': new_price})

    db.session.commit()

    return jsonify({
        'message': 'Bulk update completed',
        'updates': results
    }), 200


@products_bp.route('/export', methods=['GET'])
def export_products():
    """
    Export all products to JSON
    VULNERABILITIES:
    - API3:2023 - Includes internal data
    - API4:2023 - No limits, can export everything
    """
    # VULNERABILITY: No authentication required
    # VULNERABILITY: No limits on export size
    products = Product.query.all()

    # VULNERABILITY: Includes internal_cost and admin_notes
    export_data = []
    for product in products:
        export_data.append({
            'id': product.id,
            'name': product.name,
            'description': product.description,
            'price': product.price,
            'internal_cost': product.internal_cost,  # Should not be exported!
            'profit_margin': product.price - (product.internal_cost or 0),
            'stock': product.stock,
            'admin_notes': product.admin_notes  # Should not be exported!
        })

    return jsonify({'export': export_data}), 200
