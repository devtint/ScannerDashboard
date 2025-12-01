# Security Scanner Dashboard

A comprehensive web-based security scanning platform with real-time monitoring and detailed vulnerability reporting. Built with FastAPI, modern frontend technologies, and async architecture for efficient scanning.

![Platform Status](https://img.shields.io/badge/status-production--ready-brightgreen)
![Python](https://img.shields.io/badge/python-3.12+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.123.0-009688)
![License](https://img.shields.io/badge/license-MIT-blue)

## 🚀 Features

### Core Functionality
- **5 Production-Ready Security Scanners**
  - Security Headers Scanner (OWASP-compliant)
  - SSL/TLS Certificate Scanner
  - Cookie Security Scanner
  - CORS Policy Scanner
  - Robots & Sitemap Scanner

- **Modern Web Dashboard**
  - Real-time scan progress via WebSocket
  - Interactive results visualization
  - Scan history and statistics
  - Detailed vulnerability reports
  - Mobile-responsive design

- **Robust Architecture**
  - Async/await for high performance
  - SQLite database with full audit trail
  - RESTful API design
  - WebSocket support for live updates
  - Comprehensive error handling

### Scanner Capabilities

#### 🔒 Security Headers Scanner
- HSTS (Strict-Transport-Security)
- Content Security Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Server disclosure detection
- X-Powered-By detection
- Deprecated headers check

#### 🔐 SSL/TLS Scanner
- Certificate expiration validation
- TLS protocol version checking
- Cipher strength analysis
- Certificate chain validation
- Hostname verification
- Self-signed certificate detection

#### 🍪 Cookie Security Scanner
- Secure flag validation
- HttpOnly flag checking
- SameSite attribute verification
- Cookie expiration analysis
- Third-party cookie detection

#### 🌐 CORS Policy Scanner
- Wildcard origin detection
- Credentials misconfiguration
- Origin reflection testing
- Multiple origin validation

#### 🤖 Robots & Sitemap Scanner
- robots.txt analysis
- Sitemap.xml validation
- Sensitive path disclosure
- SEO configuration review

## 📋 Requirements

- Python 3.12+
- FastAPI 0.123.0+
- SQLAlchemy 2.0+
- Modern web browser (Chrome, Firefox, Edge, Safari)

## 🔧 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/devtint/ScannerDashboard.git
cd ScannerDashboard
```

### 2. Create Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment

```bash
# Copy example environment file
copy .env.example .env

# Edit .env with your settings (optional - works with defaults)
```

### 5. Run the Application

```bash
# Development mode
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Production mode
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

### 6. Access Dashboard

Open your browser and navigate to:
```
http://localhost:8000
```

## 🎯 Usage

### Web Dashboard

1. **Start a Scan**
   - Enter target URL (e.g., `https://example.com`)
   - Select scanners to run (or select all)
   - Click "Start Scan"
   - View real-time progress

2. **View Results**
   - See recent scans in the dashboard
   - Click on any scan for detailed results
   - Review severity-based findings
   - Monitor security posture

3. **Track Statistics**
   - Total scans performed
   - Today's scan count
   - Unique targets scanned
   - Scan history trends

### API Endpoints

#### List Available Scanners
```bash
GET /api/scanners
```

Response:
```json
{
  "scanners": [
    {
      "id": "security_headers",
      "name": "Security Headers Scanner",
      "version": "1.0.0",
      "description": "Scans HTTP security headers according to OWASP guidelines",
      "category": "Security"
    }
  ],
  "count": 5
}
```

#### Start a Scan
```bash
POST /api/scan
Content-Type: application/x-www-form-urlencoded

url=https://example.com&scanner_names=security_headers,ssl_tls
```

Response:
```json
{
  "status": "started",
  "message": "Scan initiated for https://example.com",
  "scanners": ["security_headers", "ssl_tls"]
}
```

#### Get Recent Scans
```bash
GET /api/scans/recent?limit=20
```

#### Get Scan Details
```bash
GET /api/scans/{scan_id}
```

#### Get Statistics
```bash
GET /api/statistics
```

#### WebSocket Connection
```javascript
const ws = new WebSocket('ws://localhost:8000/ws');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Scan update:', data);
};
```

## 📁 Project Structure

```
ScannerDashboard/
├── app/
│   ├── database.py          # Database configuration
│   └── models.py            # SQLAlchemy models
├── scanners/
│   ├── __init__.py          # Scanner registry
│   ├── base_scanner.py      # Base scanner interface
│   ├── security_headers.py  # Security headers scanner
│   ├── ssl_scanner.py       # SSL/TLS scanner
│   ├── cookie_scanner.py    # Cookie security scanner
│   ├── cors_scanner.py      # CORS policy scanner
│   └── robots_scanner.py    # Robots & sitemap scanner
├── templates/
│   └── index.html           # Main dashboard UI
├── static/
│   └── (static assets)
├── utils/
│   ├── helpers.py           # Utility functions
│   └── scanner_registry.py  # Scanner management
├── main.py                  # FastAPI application
├── config.py                # Configuration management
├── requirements.txt         # Python dependencies
├── .env.example            # Environment template
└── README.md               # This file
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file with the following settings (optional - all have defaults):

```ini
# Application
APP_NAME="Security Scanner Platform"
APP_VERSION="1.0.0"
DEBUG=false

# Server
HOST=0.0.0.0
PORT=8000

# Database
DATABASE_URL=sqlite:///./security_scanner.db

# Security
SECRET_KEY=your-secret-key-here
ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com

# Scanning
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT=30
DEFAULT_USER_AGENT="Security Scanner/1.0"

# Notifications (Optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-password
NOTIFICATION_EMAIL=admin@example.com
```

## 🗄️ Database Schema

The platform uses SQLite with the following tables:

- **scan_records**: Complete scan results and metadata
- **scan_history**: Aggregated statistics per scan
- **scheduled_scans**: Automated scan scheduling (planned)
- **scan_comparisons**: Compare scans over time (planned)
- **audit_logs**: Complete audit trail

## 🔐 Security Considerations

- All user inputs are validated and sanitized
- URL validation prevents SSRF attacks
- Rate limiting recommended for production
- HTTPS strongly recommended
- Environment variables for sensitive data
- SQL injection protection via ORM
- XSS protection in frontend

## 🚀 Production Deployment

### Using Gunicorn + Uvicorn

```bash
pip install gunicorn
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

### Using Docker

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Nginx Reverse Proxy

```nginx
server {
    listen 80;
    server_name scanner.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## 📊 Performance

- **Concurrent Scanning**: Up to 5 parallel scans
- **Average Scan Time**: 0.5-3 seconds per scanner
- **Database**: Optimized indexes for fast queries
- **WebSocket**: Real-time updates with minimal overhead
- **Memory**: ~100MB baseline, scales with concurrent scans

## 🧪 Testing

Run the test suite:

```bash
python test_system.py
```

Expected output:
```
✓ All scanners imported successfully
✓ Database initialized
✓ Scanner registry populated
✓ Test scan completed successfully
✓ All tests passed!
```

## 🛠️ Development

### Adding a New Scanner

1. Create scanner file in `scanners/` directory
2. Inherit from `BaseScanner`
3. Implement required methods
4. Register in `scanners/__init__.py`

Example:

```python
from scanners.base_scanner import BaseScanner, ScanResult, Severity

class MyScanner(BaseScanner):
    def __init__(self):
        self.scanner_name = "My Custom Scanner"
        self.version = "1.0.0"
    
    async def scan(self, url: str) -> List[ScanResult]:
        # Implementation
        pass
    
    def get_scanner_info(self) -> Dict:
        return {
            "name": self.scanner_name,
            "version": self.version,
            "description": "Custom scanner description",
            "category": "Security"
        }
```

Register:
```python
# scanners/__init__.py
from scanners.my_scanner import MyScanner
scanner_registry.register("my_scanner", MyScanner)
```

## 📝 Roadmap

- [ ] Add 15 additional scanners (DNS, Email, Auth, etc.)
- [ ] Scheduled scanning with cron expressions
- [ ] Email notifications for critical findings
- [ ] PDF/CSV export functionality
- [ ] Scan comparison over time
- [ ] API authentication (JWT/OAuth2)
- [ ] Rate limiting and quotas
- [ ] Multi-user support with roles
- [ ] Custom scanner plugins
- [ ] Integration with CI/CD pipelines

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- OWASP for security best practices
- FastAPI for the excellent framework
- TailwindCSS for the UI components
- Alpine.js for reactive components

## 📧 Contact

- **Repository**: [https://github.com/devtint/ScannerDashboard](https://github.com/devtint/ScannerDashboard)
- **Issues**: [https://github.com/devtint/ScannerDashboard/issues](https://github.com/devtint/ScannerDashboard/issues)

## ⭐ Star History

If you find this project helpful, please consider giving it a star!

---

**Built with ❤️ for better web security**
