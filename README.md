# OWASP Security Headers Scanner

A comprehensive, accurate, and OWASP-compliant security header scanner with beautiful colored table output.

## 🚀 Features

- **🔍 Accurate Detection**: Case-insensitive header analysis using `.lower()` and robust pattern matching
- **📋 OWASP Compliant**: Follows OWASP Application Security Verification Standard (ASVS) guidelines
- **🎨 Colored Table Output**: Beautiful justified tables with color-coded severity levels
- **🚨 Severity Classification**: Critical, High, Medium, Low, and Info severity levels
- **📊 Professional Reporting**: Clean table format with fix recommendations
- **⚡ Fast Scanning**: Efficient single-request scanning with timeout controls

## 🛡️ Security Headers Analyzed

- **Strict-Transport-Security (HSTS)** - Prevents protocol downgrade attacks
- **Content-Security-Policy (CSP)** - Prevents XSS and data injection attacks  
- **X-Frame-Options** - Prevents clickjacking attacks
- **X-Content-Type-Options** - Prevents MIME-type sniffing
- **Referrer-Policy** - Controls referrer information leakage
- **Permissions-Policy** - Controls browser feature access
- **Information Disclosure** - Detects version information in Server/X-Powered-By headers

## 📦 Installation

1. Clone the repository:
```bash
git clone https://github.com/devtint/SecurityHeaderScanner.git
cd SecurityHeaderScanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## 🎯 Usage

```bash
python header_scanner.py <URL>
```

### Examples

```bash
# Scan a website
python header_scanner.py https://github.com

# Scan without protocol (defaults to HTTPS)
python header_scanner.py example.com

# Scan HTTP site
python header_scanner.py http://insecure-site.com
```

## 📋 Sample Output

```
🔍 OWASP Security Headers Scanner
==================================================
[INFO] Scanning: https://github.com
[INFO] Response status: 200
[INFO] Total headers received: 18

========================================================================================================================
OWASP SECURITY HEADERS SCAN REPORT
========================================================================================================================
Target URL: github.com
Scan Date: 2025-12-01 03:14:12 UTC
========================================================================================================================

SECURITY SUMMARY:
  Critical Issues: 0
  High Issues:     0
  Medium Issues:   1
  Low Issues:      4

DETAILED FINDINGS:
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
HEADER NAME                         STATUS     SEVERITY     DESCRIPTION
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Content-Security-Policy             ✓ Present   MEDIUM        CSP header helps prevent XSS attacks
                                    Value: [Too long to display - see text report]
                                    Fix: Review CSP directives for overly permissive policies
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Strict-Transport-Security           ✓ Present   INFO          HSTS header enforces secure connections
                                    Value: max-age=31536000; includeSubdomains; preload
                                    Fix: Ensure max-age is sufficient (recommended: 31536000 seconds or more)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

📄 Report saved to: security_headers_report_github_com.txt

✅ No critical security issues found!
```

## 🎨 Color Coding

- 🔴 **Critical/High**: Bright red - Immediate attention required
- 🟡 **Medium**: Yellow - Should be addressed  
- 🔵 **Low**: Blue - Minor improvements
- 🟢 **Info/Good**: Green - Properly configured
- ✅ **Present**: Green checkmark
- ❌ **Missing**: Red X

## 📊 Exit Codes

- `0` - Scan completed successfully with no critical/high issues
- `1` - Scan failed or critical/high severity issues found

## 🔧 Dependencies

- `requests>=2.28.0` - HTTP requests
- `urllib3>=1.26.0` - HTTP client
- `colorama>=0.4.4` - Cross-platform colored output

## 📝 OWASP Compliance

This scanner implements checks based on:

- **OWASP ASVS 4.0** (Application Security Verification Standard)
- **OWASP Top 10 2021** 
- **OWASP Secure Headers Project**
- **Mozilla Observatory** recommendations

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for security assessment purposes only. Always test in non-production environments first.

## 🔗 Links

- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla Observatory](https://observatory.mozilla.org/)

---

Made with ❤️ for better web security