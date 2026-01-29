# VulnAPI-101: Purposefully Vulnerable API

> **WARNING:** This application is intentionally vulnerable for educational purposes. DO NOT deploy in production or expose to the internet!

VulnAPI-101 is a deliberately vulnerable REST API designed for learning and practicing API security testing. It incorporates all OWASP API Security Top 10 (2023) vulnerabilities.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python run.py
```

Access the application:
- **API:** http://localhost:5000/api
- **Web Interface:** http://localhost:5000/
- **Vulnerability Guides:** http://localhost:5000/guides/

## Test Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | admin |
| john | password123 | user |
| jane | jane2024 | user |
| test | test | user |

## OWASP API Top 10 Vulnerabilities

### API1:2023 - Broken Object Level Authorization (BOLA)
- Access any user's data by changing IDs
- View/modify/delete orders belonging to others
- **Endpoints:** `/api/users/{id}`, `/api/orders/{id}`

### API2:2023 - Broken Authentication
- Plain text password storage
- Weak JWT secret key
- No rate limiting on login
- User enumeration via error messages
- Weak 6-digit reset tokens
- **Endpoints:** `/api/auth/*`

### API3:2023 - Broken Object Property Level Authorization
- Sensitive data exposure (SSN, credit cards, passwords in responses)
- Mass assignment (set role, balance during registration)
- Internal costs and admin notes exposed
- **Endpoints:** `/api/users`, `/api/products`, `/api/auth/register`

### API4:2023 - Unrestricted Resource Consumption
- No pagination on list endpoints
- No rate limiting
- Large file uploads allowed (100MB)
- Unlimited bulk operations
- **Endpoints:** All list endpoints, `/api/files/upload`

### API5:2023 - Broken Function Level Authorization (BFLA)
- Admin endpoints accessible to regular users
- Any user can change roles, create coupons, view config
- Raw SQL execution without admin check
- **Endpoints:** `/api/admin/*`

### API6:2023 - Unrestricted Access to Sensitive Business Flows
- Price manipulation in orders
- Order status bypass
- Multiple refunds for same order
- Unlimited balance addition
- Coupon abuse
- **Endpoints:** `/api/orders`, `/api/users/me/balance`

### API7:2023 - Server Side Request Forgery (SSRF)
- Fetch arbitrary URLs including internal services
- Weak validation bypass (IP formats)
- Full HTTP proxy functionality
- Webhook SSRF
- **Endpoints:** `/api/files/fetch`, `/api/files/proxy`, `/api/files/webhook`

### API8:2023 - Security Misconfiguration
- Debug mode enabled
- Verbose error messages with stack traces
- Hardcoded secrets
- Remote code execution via debug endpoints
- Path traversal in file operations
- Permissive CORS (*)
- **Endpoints:** `/api/debug/*`, `/api/admin/database/query`

### API9:2023 - Improper Inventory Management
- Hidden/undocumented endpoints
- Route listing endpoint
- Deprecated endpoints still accessible
- **Endpoints:** `/api/debug/.hidden`, `/api/admin/hidden/*`

### API10:2023 - Unsafe Consumption of APIs
- External API data processed without validation
- Webhook callbacks trusted implicitly
- **Endpoints:** `/api/files/import-data`

## Project Structure

```
vulnapi-101/
├── app/
│   ├── __init__.py      # Flask app factory
│   ├── config.py        # Configuration (with hardcoded secrets)
│   ├── models.py        # Database models
│   ├── utils.py         # Utility functions
│   └── routes/
│       ├── auth.py      # Authentication routes
│       ├── users.py     # User management routes
│       ├── products.py  # Product routes
│       ├── orders.py    # Order routes
│       ├── admin.py     # Admin routes
│       ├── files.py     # File/SSRF routes
│       └── debug.py     # Debug routes
├── static/
│   ├── css/style.css    # Styles
│   ├── js/app.js        # Frontend JavaScript
│   └── index.html       # Main web interface
├── guides/
│   ├── index.html       # Guide index
│   ├── by-vulnerability.html
│   ├── by-file.html
│   └── vulnerabilities/ # Individual vulnerability guides
├── run.py               # Application entry point
└── requirements.txt     # Python dependencies
```

## Usage Examples

### Login and Get Token
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

### BOLA - Access Other User's Data
```bash
curl http://localhost:5000/api/users/1
```

### Mass Assignment - Register as Admin
```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "hacker", "email": "h@h.com", "password": "hack", "role": "admin"}'
```

### SSRF - Access Internal Resources
```bash
curl -X POST http://localhost:5000/api/files/fetch \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://localhost:5000/api/debug/.hidden"}'
```

### RCE - Execute Code
```bash
curl -X POST http://localhost:5000/api/debug/execute \
  -H "Content-Type: application/json" \
  -d '{"code": "import os; result = os.getcwd()"}'
```

## Future Plans

- Docker containerization with docker-compose
- Separate frontend and backend containers
- Network segmentation for realistic attack scenarios
- Additional vulnerability scenarios

## Disclaimer

This project is for **educational purposes only**. Use it to:
- Learn about API security vulnerabilities
- Practice penetration testing techniques
- Understand the OWASP API Top 10

**Never** use the techniques learned here against systems without explicit authorization.

## License

MIT License - Use at your own risk for educational purposes.
