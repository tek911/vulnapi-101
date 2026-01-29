"""
Configuration file for VulnAPI-101
VULNERABILITY: API8:2023 - Security Misconfiguration
- Debug mode enabled in production
- Hardcoded secret key
- Overly permissive CORS
- Verbose error messages enabled
"""

import os

class Config:
    # VULNERABILITY: Hardcoded secret key (Security Misconfiguration)
    SECRET_KEY = 'super-secret-key-12345'

    # VULNERABILITY: Debug mode enabled (Security Misconfiguration)
    DEBUG = True

    # Database configuration
    SQLALCHEMY_DATABASE_URI = 'sqlite:///vulnapi.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # VULNERABILITY: JWT with weak secret (Broken Authentication)
    JWT_SECRET = 'jwt-secret-weak'
    JWT_ALGORITHM = 'HS256'

    # VULNERABILITY: No token expiration enforcement
    JWT_EXPIRATION_HOURS = 8760  # 1 year - way too long

    # VULNERABILITY: Overly permissive CORS (Security Misconfiguration)
    CORS_ORIGINS = '*'
    CORS_ALLOW_HEADERS = '*'
    CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']

    # VULNERABILITY: Verbose errors (Security Misconfiguration)
    PROPAGATE_EXCEPTIONS = True

    # Admin credentials - VULNERABILITY: Hardcoded credentials
    ADMIN_USERNAME = 'admin'
    ADMIN_PASSWORD = 'admin123'

    # VULNERABILITY: No rate limiting configuration
    RATE_LIMIT_ENABLED = False

    # File upload settings - VULNERABILITY: Unrestricted uploads
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB - too large
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'html', 'js', 'php', 'py'}  # Dangerous extensions allowed
