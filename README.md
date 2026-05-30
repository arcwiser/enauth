# EnAuth

A comprehensive authentication and licensing system with support for license keys, HWID binding, multi-level products, resellers, and a full admin panel.

## Features

- **License Management**: Create, manage, and revoke license keys with expiration dates
- **HWID Binding**: Secure hardware ID binding with configurable limits per license
- **Multi-Level Products**: Support for different product tiers and pricing
- **Reseller System**: Built-in reseller management with balance and pricing controls
- **Admin Panel**: Full-featured web interface for managing all aspects of the system
- **Two-Factor Authentication**: TOTP-based 2FA for admin accounts
- **Security**: AES-256-GCM encryption, HMAC signatures, rate limiting, and replay protection
- **C++ SDK**: Client SDK for Windows applications with anti-debugging features
- **Audit Logging**: Comprehensive logging of all actions

## Installation

### Prerequisites

- Python 3.12 or later
- pip package manager

### Quick Start

1. Clone the repository:
```bash
git clone <repository-url>
cd server
```

2. Install dependencies:
```bash
# Windows
install_deps.bat

# Linux/Mac
pip install -r requirements.txt
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Run the server:
```bash
# Windows
start_server.bat

# Linux/Mac
python main.py
```

5. Access the admin panel:
```
http://localhost:8080/panel/
```

## Configuration

Environment variables (see `.env.example`):

- `HOST`: Server host (default: 0.0.0.0)
- `PORT`: Server port (default: 8080)
- `DEBUG`: Enable debug mode (default: false)
- `DB_PATH`: Database file path (default: enauth.db)
- `ADMIN_USERNAME`: Default admin username
- `ADMIN_PASSWORD`: Default admin password (auto-generated if not set)
- `CORS_ORIGINS`: Comma-separated list of allowed origins
- `SSL_CERT`: Path to SSL certificate file
- `SSL_KEY`: Path to SSL key file

### Security Settings

- `TIMESTAMP_TOLERANCE`: Request timestamp tolerance in seconds (default: 60)
- `SESSION_DURATION`: Client session duration in seconds (default: 86400)
- `MAX_LOGIN_STRIKES`: Maximum failed login attempts before lockout (default: 5)
- `NONCE_CACHE_SIZE`: Maximum nonces to remember for replay protection (default: 10000)
- `NONCE_TTL`: Nonce time-to-live in seconds (default: 120)

### Rate Limiting

- `RATE_LIMIT_INIT`: Init endpoint (default: 20/minute)
- `RATE_LIMIT_NEWS`: News endpoint (default: 15/minute)
- `RATE_LIMIT_LOGIN`: Login endpoint (default: 8/minute)
- `RATE_LIMIT_HEARTBEAT`: Heartbeat endpoint (default: 60/minute)
- `RATE_LIMIT_LOGOUT`: Logout endpoint (default: 20/minute)
- `RATE_LIMIT_VALIDATE`: Validate endpoint (default: 30/minute)
- `RATE_LIMIT_DOWNLOAD`: Download endpoint (default: 10/minute)

## Docker Deployment

### Using Docker Compose

```bash
docker-compose up -d
```

### Using Docker

```bash
docker build -t enauth .
docker run -p 8080:8080 -v $(pwd)/data:/app/data enauth
```

## API Documentation

When running in debug mode (`DEBUG=true`), API documentation is available at:
- Swagger UI: `http://localhost:8080/docs`
- ReDoc: `http://localhost:8080/redoc`

## Client SDK Integration

See `sdk/README.md` for detailed C++ SDK integration instructions.

Basic usage:
```cpp
#include "enauth.h"

enauth::Client client(
    "https://your-server.com",
    "your-app-id",
    "your-app-secret",
    "1.0.0"
);

auto result = client.Init();
if (result.success) {
    auto login = client.Login("YOUR-LICENSE-KEY");
    if (login.success) {
        // Application authenticated
    }
}
```

## Database Schema

The system uses SQLite with the following main tables:
- `applications`: Application definitions
- `licenses`: License keys and their properties
- `hwids`: Hardware ID bindings
- `sessions`: Active client sessions
- `admin_users`: Admin accounts
- `products`: Product tiers
- `resellers`: Reseller accounts
- `logs`: Audit log

## Security Considerations

- All client communication is encrypted with AES-256-GCM
- HMAC signatures prevent request tampering
- Nonce-based replay protection
- Rate limiting on all endpoints
- HWID validation requires SHA-256/512 hashes
- Brute force protection with strike counting

## License

This project is provided as-is for authentication and licensing purposes.

## Support

For issues and questions, please refer to the project documentation or contact the maintainers.
