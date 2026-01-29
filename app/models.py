"""
Database models for VulnAPI-101
Contains User, Product, Order, Comment, and other models
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    """User model with deliberately vulnerable fields"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # VULNERABILITY: Passwords stored in plain text (Broken Authentication)
    password = db.Column(db.String(120), nullable=False)
    # VULNERABILITY: Sensitive data exposed (Broken Object Property Level Authorization)
    ssn = db.Column(db.String(11), nullable=True)  # Social Security Number
    credit_card = db.Column(db.String(19), nullable=True)
    role = db.Column(db.String(20), default='user')  # user, admin, moderator
    is_active = db.Column(db.Boolean, default=True)
    api_key = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    balance = db.Column(db.Float, default=100.0)
    reset_token = db.Column(db.String(64), nullable=True)
    # VULNERABILITY: Internal notes exposed
    internal_notes = db.Column(db.Text, nullable=True)

    orders = db.relationship('Order', backref='user', lazy=True)
    comments = db.relationship('Comment', backref='user', lazy=True)

    def to_dict(self, include_sensitive=True):
        """Convert user to dictionary
        VULNERABILITY: By default includes sensitive data (API3 - Broken Object Property Level Authorization)
        """
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'balance': self.balance
        }
        # VULNERABILITY: Sensitive data always included
        if include_sensitive:
            data['ssn'] = self.ssn
            data['credit_card'] = self.credit_card
            data['api_key'] = self.api_key
            data['internal_notes'] = self.internal_notes
            data['password'] = self.password  # CRITICAL: Password exposed!
        return data


class Product(db.Model):
    """Product model for e-commerce functionality"""
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)
    # VULNERABILITY: Internal cost exposed (Broken Object Property Level Authorization)
    internal_cost = db.Column(db.Float, nullable=True)
    stock = db.Column(db.Integer, default=0)
    category = db.Column(db.String(50), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    # VULNERABILITY: Admin notes exposed
    admin_notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self, include_internal=True):
        """Convert product to dictionary
        VULNERABILITY: Internal data exposed by default
        """
        data = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'stock': self.stock,
            'category': self.category,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        if include_internal:
            data['internal_cost'] = self.internal_cost
            data['admin_notes'] = self.admin_notes
        return data


class Order(db.Model):
    """Order model for e-commerce functionality"""
    __tablename__ = 'orders'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    total_price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, confirmed, shipped, delivered
    shipping_address = db.Column(db.Text, nullable=True)
    # VULNERABILITY: Payment info stored
    payment_method = db.Column(db.String(50), nullable=True)
    card_last_four = db.Column(db.String(4), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # VULNERABILITY: Internal tracking data
    internal_tracking = db.Column(db.String(100), nullable=True)
    profit_margin = db.Column(db.Float, nullable=True)

    product = db.relationship('Product', backref='orders')

    def to_dict(self):
        """Convert order to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'product_id': self.product_id,
            'product_name': self.product.name if self.product else None,
            'quantity': self.quantity,
            'total_price': self.total_price,
            'status': self.status,
            'shipping_address': self.shipping_address,
            'payment_method': self.payment_method,
            'card_last_four': self.card_last_four,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'internal_tracking': self.internal_tracking,
            'profit_margin': self.profit_margin
        }


class Comment(db.Model):
    """Comment/Review model"""
    __tablename__ = 'comments'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=True)
    content = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, nullable=True)
    is_approved = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    product = db.relationship('Product', backref='comments')

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else None,
            'product_id': self.product_id,
            'content': self.content,
            'rating': self.rating,
            'is_approved': self.is_approved,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Coupon(db.Model):
    """Coupon model for discounts"""
    __tablename__ = 'coupons'

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    discount_percent = db.Column(db.Float, nullable=False)
    max_uses = db.Column(db.Integer, default=100)
    current_uses = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    # VULNERABILITY: Internal-only coupons exposed
    is_internal = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'code': self.code,
            'discount_percent': self.discount_percent,
            'max_uses': self.max_uses,
            'current_uses': self.current_uses,
            'is_active': self.is_active,
            'is_internal': self.is_internal
        }


class AuditLog(db.Model):
    """Audit log for tracking actions - should be admin only"""
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'details': self.details,
            'ip_address': self.ip_address,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
