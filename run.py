#!/usr/bin/env python3
"""
VulnAPI-101 - Main entry point
Purposefully Vulnerable API for Security Training

WARNING: This application is intentionally vulnerable!
DO NOT deploy in production or expose to the internet!
"""

import os
import sys

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, init_db

app = create_app()

if __name__ == '__main__':
    # Initialize database with sample data
    init_db(app)

    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗ █████╗ ██████╗ ██╗    ║
    ║   ██║   ██║██║   ██║██║     ████╗  ██║██╔══██╗██╔══██╗██║    ║
    ║   ██║   ██║██║   ██║██║     ██╔██╗ ██║███████║██████╔╝██║    ║
    ║   ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██╔═══╝ ██║    ║
    ║    ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║██║     ██║    ║
    ║     ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝    ║
    ║                                                               ║
    ║             Purposefully Vulnerable API - v1.0.0              ║
    ║                                                               ║
    ║   ⚠️  WARNING: This API contains intentional vulnerabilities! ║
    ║   DO NOT deploy in production or expose to the internet!      ║
    ║                                                               ║
    ║   API:    http://localhost:5000/api                           ║
    ║   Web:    http://localhost:5000/                              ║
    ║   Guides: http://localhost:5000/guides/                       ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)

    # VULNERABILITY: Debug mode enabled, binding to all interfaces
    app.run(
        host='0.0.0.0',  # VULNERABILITY: Binds to all interfaces
        port=5000,
        debug=True,  # VULNERABILITY: Debug mode in production
        threaded=True
    )
