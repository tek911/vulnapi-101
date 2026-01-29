"""
VulnAPI-101 - Purposefully Vulnerable API for Security Training
This application contains OWASP API Top 10 vulnerabilities for educational purposes.
DO NOT DEPLOY THIS IN PRODUCTION!
"""

from flask import Flask, jsonify
from flask_cors import CORS
from app.config import Config
from app.models import db


def create_app(config_class=Config):
    """Create and configure the Flask application"""
    app = Flask(__name__,
                static_folder='../static',
                template_folder='../templates')

    app.config.from_object(config_class)

    # VULNERABILITY: API8:2023 - Overly permissive CORS
    CORS(app,
         origins='*',
         allow_headers='*',
         methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
         supports_credentials=True)

    # Initialize database
    db.init_app(app)

    # Register blueprints
    from app.routes import (
        auth_bp, users_bp, products_bp,
        orders_bp, admin_bp, files_bp, debug_bp
    )

    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(products_bp)
    app.register_blueprint(orders_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(debug_bp)

    # VULNERABILITY: API8:2023 - Verbose error handlers
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({
            'error': 'Bad Request',
            'message': str(e),
            'details': e.description if hasattr(e, 'description') else None
        }), 400

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({
            'error': 'Not Found',
            'message': str(e),
            'path': str(e)
        }), 404

    @app.errorhandler(500)
    def internal_error(e):
        import traceback
        return jsonify({
            'error': 'Internal Server Error',
            'message': str(e),
            'traceback': traceback.format_exc()  # VULNERABILITY: Stack trace exposed
        }), 500

    # API root endpoint
    @app.route('/api')
    def api_root():
        return jsonify({
            'name': 'VulnAPI-101',
            'version': '1.0.0',
            'description': 'Purposefully vulnerable API for security training',
            'warning': 'DO NOT USE IN PRODUCTION!',
            'endpoints': {
                'auth': '/api/auth',
                'users': '/api/users',
                'products': '/api/products',
                'orders': '/api/orders',
                'admin': '/api/admin',
                'files': '/api/files',
                'debug': '/api/debug'
            }
        }), 200

    @app.route('/')
    def index():
        from flask import redirect
        return redirect('/index.html')

    # Health check endpoint
    @app.route('/health')
    def health():
        return jsonify({'status': 'ok'}), 200

    return app


def init_db(app):
    """Initialize database with sample data"""
    with app.app_context():
        db.create_all()

        from app.models import User, Product, Order, Coupon, Comment

        # Check if data already exists
        if User.query.first() is None:
            # Create sample users
            users = [
                User(
                    username='admin',
                    email='admin@vulnapi.local',
                    password='admin123',  # Plain text - vulnerable
                    role='admin',
                    balance=10000.00,
                    ssn='123-45-6789',
                    credit_card='4111-1111-1111-1111',
                    api_key='admin-api-key-12345',
                    internal_notes='Administrator account - full access'
                ),
                User(
                    username='john',
                    email='john@example.com',
                    password='password123',
                    role='user',
                    balance=500.00,
                    ssn='987-65-4321',
                    credit_card='5555-5555-5555-4444',
                    api_key='john-api-key-abcdef',
                    internal_notes='Regular user - premium member'
                ),
                User(
                    username='jane',
                    email='jane@example.com',
                    password='jane2024',
                    role='user',
                    balance=250.00,
                    ssn='456-78-9012',
                    credit_card='3782-822463-10005',
                    api_key='jane-api-key-xyz789'
                ),
                User(
                    username='moderator',
                    email='mod@vulnapi.local',
                    password='mod123',
                    role='moderator',
                    balance=1000.00,
                    api_key='mod-api-key-qwerty'
                ),
                User(
                    username='test',
                    email='test@test.com',
                    password='test',
                    role='user',
                    balance=100.00,
                    api_key='test-api-key-000000'
                )
            ]

            for user in users:
                db.session.add(user)

            # Create sample products
            products = [
                Product(
                    name='Premium Widget',
                    description='A high-quality widget for all your needs',
                    price=99.99,
                    internal_cost=25.00,
                    stock=100,
                    category='widgets',
                    admin_notes='Best seller - 75% margin'
                ),
                Product(
                    name='Basic Gadget',
                    description='An affordable gadget for everyday use',
                    price=29.99,
                    internal_cost=10.00,
                    stock=500,
                    category='gadgets',
                    admin_notes='Entry level product'
                ),
                Product(
                    name='Deluxe Package',
                    description='Our premium package with all features',
                    price=199.99,
                    internal_cost=50.00,
                    stock=25,
                    category='packages',
                    admin_notes='High margin - push in marketing'
                ),
                Product(
                    name='Secret Internal Product',
                    description='This product should not be visible to users',
                    price=9999.99,
                    internal_cost=1.00,
                    stock=1,
                    category='internal',
                    is_active=False,
                    admin_notes='TEST ONLY - DO NOT SELL'
                ),
                Product(
                    name='Limited Edition',
                    description='Exclusive limited edition item',
                    price=499.99,
                    internal_cost=100.00,
                    stock=10,
                    category='exclusive',
                    admin_notes='VIP customers only'
                )
            ]

            for product in products:
                db.session.add(product)

            db.session.commit()

            # Create sample orders (need user and product IDs)
            orders = [
                Order(
                    user_id=2,  # john
                    product_id=1,
                    quantity=2,
                    total_price=199.98,
                    status='delivered',
                    shipping_address='123 Main St, City, ST 12345',
                    payment_method='credit_card',
                    card_last_four='4444',
                    internal_tracking='TRACK123456',
                    profit_margin=149.98
                ),
                Order(
                    user_id=3,  # jane
                    product_id=2,
                    quantity=1,
                    total_price=29.99,
                    status='shipped',
                    shipping_address='456 Oak Ave, Town, ST 67890',
                    payment_method='credit_card',
                    card_last_four='0005',
                    internal_tracking='TRACK789012',
                    profit_margin=19.99
                ),
                Order(
                    user_id=2,  # john
                    product_id=3,
                    quantity=1,
                    total_price=199.99,
                    status='pending',
                    shipping_address='123 Main St, City, ST 12345',
                    payment_method='paypal',
                    internal_tracking='TRACK345678',
                    profit_margin=149.99
                )
            ]

            for order in orders:
                db.session.add(order)

            # Create sample coupons
            coupons = [
                Coupon(
                    code='WELCOME10',
                    discount_percent=10.0,
                    max_uses=1000,
                    current_uses=50,
                    is_active=True,
                    is_internal=False
                ),
                Coupon(
                    code='SUMMER25',
                    discount_percent=25.0,
                    max_uses=500,
                    current_uses=100,
                    is_active=True,
                    is_internal=False
                ),
                Coupon(
                    code='INTERNAL50',
                    discount_percent=50.0,
                    max_uses=10,
                    current_uses=0,
                    is_active=True,
                    is_internal=True  # Internal use only - should not be exposed!
                ),
                Coupon(
                    code='EMPLOYEE75',
                    discount_percent=75.0,
                    max_uses=100,
                    current_uses=5,
                    is_active=True,
                    is_internal=True
                ),
                Coupon(
                    code='FREEBIE100',
                    discount_percent=100.0,
                    max_uses=5,
                    current_uses=2,
                    is_active=True,
                    is_internal=True  # 100% off - employees only!
                )
            ]

            for coupon in coupons:
                db.session.add(coupon)

            # Create sample comments
            comments = [
                Comment(
                    user_id=2,
                    product_id=1,
                    content='Great product! Highly recommended.',
                    rating=5,
                    is_approved=True
                ),
                Comment(
                    user_id=3,
                    product_id=1,
                    content='Good value for money.',
                    rating=4,
                    is_approved=True
                ),
                Comment(
                    user_id=2,
                    product_id=2,
                    content='Decent quality for the price.',
                    rating=3,
                    is_approved=True
                )
            ]

            for comment in comments:
                db.session.add(comment)

            db.session.commit()
            print("Database initialized with sample data!")
