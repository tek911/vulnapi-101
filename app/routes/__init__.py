"""
Routes package for VulnAPI-101
"""

from flask import Blueprint

# Import all route blueprints
from app.routes.auth import auth_bp
from app.routes.users import users_bp
from app.routes.products import products_bp
from app.routes.orders import orders_bp
from app.routes.admin import admin_bp
from app.routes.files import files_bp
from app.routes.debug import debug_bp

__all__ = [
    'auth_bp',
    'users_bp',
    'products_bp',
    'orders_bp',
    'admin_bp',
    'files_bp',
    'debug_bp'
]
