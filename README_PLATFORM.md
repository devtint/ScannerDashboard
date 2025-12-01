# Security Scanner Platform

A comprehensive web-based security scanning platform with 20+ security scanners integrated into a modern FastAPI dashboard.

## 🚀 Features

- **Multiple Security Scanners**: 5+ scanners including Security Headers, SSL/TLS, Cookies, CORS, and Robots.txt
- **Real-time Updates**: WebSocket-powered live scan progress
- **Modern Dashboard**: Beautiful, responsive UI with TailwindCSS
- **Historical Data**: Store and analyze scan history
- **Security Scoring**: Automatic security score calculation
- **Export Reports**: Download scan results in multiple formats
- **RESTful API**: Full API access for automation

## 📦 Installation

1. **Clone the repository**
```bash
git clone https://github.com/devtint/SecurityHeaderScanner.git
cd SecurityHeaderScanner
```

2. **Install dependencies**
```bash
pip install -r requirements_web.txt
```

3. **Configure environment**
```bash
copy .env.example .env
# Edit .env with your settings
```

4. **Start the server**

**Windows:**
```bash
start_server.bat
```

**Linux/Mac:**
```bash
python main.py
```

## 🎯 Usage

### Web Dashboard

1. Open browser to `http://localhost:8000`
2. Enter target URL
3. Select scanners to run
4. Click "Start Scan"
5. View real-time results

### API Usage

**List Available Scanners:**
```bash
curl http://localhost:8000/api/scanners
```

**Start a Scan:**
```bash
curl -X POST "http://localhost:8000/api/scan?url=https://example.com&scanner_names=security_headers&scanner_names=ssl_tls"
```

**Get Recent Scans:**
```bash
curl http://localhost:8000/api/scans/recent
```

**Get Scan Details:**
```bash
curl http://localhost:8000/api/scans/1
```

**Get Statistics:**
```bash
curl http://localhost:8000/api/statistics
```

## 🔍 Available Scanners

### Currently Implemented

1. **Security Headers Scanner** - OWASP-compliant HTTP security headers analysis
2. **SSL/TLS Scanner** - Certificate validation and encryption analysis
3. **Cookie Security Scanner** - Cookie attribute security checks
4. **CORS Policy Scanner** - Cross-origin resource sharing misconfiguration detection
5. **Robots & Sitemap Scanner** - SEO and information disclosure analysis

### Coming Soon

6. Subdomain Enumeration
7. Directory/File Fuzzer
8. Form Security Analyzer
9. Email Harvester & Validator
10. JavaScript Library Scanner
11. Meta Tag Analyzer
12. Page Speed Analyzer
13. Accessibility Scanner
14. GDPR Compliance Checker
15. Mobile Responsiveness
16. DNS Record Analyzer
17. Technology Stack Detector
18. Broken Link Checker
19. Social Media Integration
20. API Endpoint Scanner

## 🏗️ Architecture

```
SecurityHeaderScanner/
├── app/                    # FastAPI application
│   ├── models.py          # Database models
│   └── database.py        # Database configuration
├── scanners/              # Security scanners
│   ├── base_scanner.py    # Base scanner interface
│   ├── security_headers.py
│   ├── ssl_scanner.py
│   ├── cookie_scanner.py
│   ├── cors_scanner.py
│   └── robots_scanner.py
├── templates/             # HTML templates
│   └── index.html        # Dashboard UI
├── static/               # Static files (CSS, JS)
├── utils/                # Utility functions
│   ├── helpers.py
│   └── scanner_registry.py
├── config.py             # Configuration
├── main.py              # FastAPI application
└── requirements_web.txt # Dependencies
```

## 🛠️ Technology Stack

- **Backend**: FastAPI, Python 3.8+
- **Database**: SQLAlchemy (SQLite/PostgreSQL)
- **Frontend**: TailwindCSS, Alpine.js, Chart.js
- **Real-time**: WebSocket
- **Async**: httpx, aiohttp

## 🔐 Security Best Practices

- All scanners use case-insensitive header detection
- Severity-based classification (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- OWASP guidelines compliance
- Secure configuration defaults
- Input validation and sanitization

## 📊 Database Schema

- **scan_records**: Individual scan results
- **scan_history**: Historical analytics
- **scheduled_scans**: Automated scan configuration
- **scan_comparisons**: Change tracking
- **audit_logs**: Security audit trail

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

MIT License - See LICENSE file for details

## 👤 Author

**devtint**
- GitHub: [@devtint](https://github.com/devtint)
- Repository: [SecurityHeaderScanner](https://github.com/devtint/SecurityHeaderScanner)

## 🙏 Acknowledgments

- OWASP for security guidelines
- FastAPI community
- All open-source contributors

## 📝 Changelog

### v1.0.0 (2025-12-01)
- Initial release with 5 core scanners
- FastAPI web dashboard
- Real-time WebSocket updates
- Database storage and history
- RESTful API
- Security scoring system

---

**Note**: This tool is for educational and authorized security testing only. Always get permission before scanning any website.
