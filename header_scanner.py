#!/usr/bin/env python3
"""
OWASP Security Headers Scanner
A comprehensive tool to analyze HTTP security headers according to OWASP guidelines.
Features accurate detection using case-insensitive comparisons and thorough validation.
"""

import requests
import urllib3
from urllib.parse import urlparse
import sys
import json
import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)  # Initialize colorama for Windows
    COLORS_ENABLED = True
except ImportError:
    # Fallback if colorama is not installed
    class MockColor:
        def __getattr__(self, name):
            return ''
    Fore = Back = Style = MockColor()
    COLORS_ENABLED = False
try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)  # Initialize colorama for Windows
    COLORS_ENABLED = True
except ImportError:
    # Fallback if colorama is not installed
    class MockColor:
        def __getattr__(self, name):
            return ''
    Fore = Back = Style = MockColor()
    COLORS_ENABLED = False

# Suppress SSL warnings for testing purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class HeaderCheck:
    header: str
    present: bool
    value: Optional[str]
    severity: Severity
    description: str
    recommendation: str
    owasp_reference: str

class OWASPHeaderScanner:
    """
    OWASP-compliant security header scanner with accurate case-insensitive detection
    """
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        
        # User agent to avoid blocking
        self.session.headers.update({
            'User-Agent': 'OWASP-Header-Scanner/1.0 (Security Assessment Tool)'
        })
    
    def _colorize_severity(self, severity: Severity) -> str:
        """Apply color to severity levels"""
        colors = {
            Severity.CRITICAL: Fore.RED + Style.BRIGHT,
            Severity.HIGH: Fore.RED,
            Severity.MEDIUM: Fore.YELLOW,
            Severity.LOW: Fore.BLUE,
            Severity.INFO: Fore.GREEN
        }
        return f"{colors.get(severity, '')}{severity.value}{Style.RESET_ALL}"
    
    def _colorize_status(self, status: bool) -> str:
        """Apply color to present/missing status"""
        if status:
            return f"{Fore.GREEN}✓ Present{Style.RESET_ALL}"
        else:
            return f"{Fore.RED}✗ Missing{Style.RESET_ALL}"
    
    def _colorize_text(self, text: str, color: str) -> str:
        """Apply color to text"""
        return f"{color}{text}{Style.RESET_ALL}"
    
    def _colorize_severity(self, severity: Severity) -> str:
        """Apply color to severity levels"""
        colors = {
            Severity.CRITICAL: Fore.RED + Style.BRIGHT,
            Severity.HIGH: Fore.RED,
            Severity.MEDIUM: Fore.YELLOW,
            Severity.LOW: Fore.BLUE,
            Severity.INFO: Fore.GREEN
        }
        return f"{colors.get(severity, '')}{severity.value}{Style.RESET_ALL}"
    
    def _colorize_status(self, status: bool) -> str:
        """Apply color to present/missing status"""
        if status:
            return f"{Fore.GREEN}✓ Present{Style.RESET_ALL}"
        else:
            return f"{Fore.RED}✗ Missing{Style.RESET_ALL}"
    
    def _colorize_text(self, text: str, color: str) -> str:
        """Apply color to text"""
        return f"{color}{text}{Style.RESET_ALL}"
    
    def scan_url(self, url: str) -> Dict[str, HeaderCheck]:
        """
        Scan a URL for security headers
        
        Args:
            url: The URL to scan
            
        Returns:
            Dictionary of header checks
        """
        try:
            # Normalize URL
            if not url.startswith(('http://', 'https://')):
                url = f'https://{url}'
            
            print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Scanning: {Fore.WHITE + Style.BRIGHT}{url}{Style.RESET_ALL}")
            
            # Make request
            response = self.session.get(
                url, 
                timeout=self.timeout, 
                verify=self.verify_ssl,
                allow_redirects=True
            )
            
            # Convert all headers to lowercase for accurate comparison
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            
            status_color = Fore.GREEN if response.status_code == 200 else Fore.YELLOW
            print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Response status: {status_color}{response.status_code}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Total headers received: {Fore.MAGENTA}{len(response.headers)}{Style.RESET_ALL}")
            
            # Perform security header checks
            results = {}
            results.update(self._check_security_headers(headers_lower))
            results.update(self._check_information_disclosure(headers_lower))
            results.update(self._check_deprecated_headers(headers_lower))
            
            return results
            
        except requests.exceptions.Timeout:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Timeout while connecting to {url}")
            return {}
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Connection error to {url}")
            return {}
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Request failed: {e}")
            return {}
    
    def _check_security_headers(self, headers: Dict[str, str]) -> Dict[str, HeaderCheck]:
        """Check for presence and validity of security headers"""
        checks = {}
        
        # Strict-Transport-Security (HSTS)
        hsts_header = headers.get('strict-transport-security')
        if hsts_header:
            # Parse HSTS value for accuracy
            is_valid_hsts = self._validate_hsts(hsts_header)
            severity = Severity.INFO if is_valid_hsts else Severity.MEDIUM
            checks['hsts'] = HeaderCheck(
                header='Strict-Transport-Security',
                present=True,
                value=hsts_header,
                severity=severity,
                description='HSTS header enforces secure connections',
                recommendation='Ensure max-age is sufficient (recommended: 31536000 seconds or more)',
                owasp_reference='OWASP ASVS V9.2.1'
            )
        else:
            checks['hsts'] = HeaderCheck(
                header='Strict-Transport-Security',
                present=False,
                value=None,
                severity=Severity.HIGH,
                description='Missing HSTS header - connections may be vulnerable to downgrade attacks',
                recommendation='Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                owasp_reference='OWASP ASVS V9.2.1'
            )
        
        # Content-Security-Policy (CSP)
        csp_header = headers.get('content-security-policy')
        if csp_header:
            is_valid_csp = self._validate_csp(csp_header)
            severity = Severity.INFO if is_valid_csp else Severity.MEDIUM
            checks['csp'] = HeaderCheck(
                header='Content-Security-Policy',
                present=True,
                value=csp_header,
                severity=severity,
                description='CSP header helps prevent XSS attacks',
                recommendation='Review CSP directives for overly permissive policies',
                owasp_reference='OWASP ASVS V14.4.1'
            )
        else:
            checks['csp'] = HeaderCheck(
                header='Content-Security-Policy',
                present=False,
                value=None,
                severity=Severity.HIGH,
                description='Missing CSP header - vulnerable to XSS attacks',
                recommendation='Implement Content-Security-Policy with restrictive directives',
                owasp_reference='OWASP ASVS V14.4.1'
            )
        
        # X-Frame-Options
        xframe_header = headers.get('x-frame-options')
        if xframe_header:
            is_valid_xframe = xframe_header.lower().strip() in ['deny', 'sameorigin']
            severity = Severity.INFO if is_valid_xframe else Severity.MEDIUM
            checks['x_frame_options'] = HeaderCheck(
                header='X-Frame-Options',
                present=True,
                value=xframe_header,
                severity=severity,
                description='X-Frame-Options helps prevent clickjacking',
                recommendation='Use DENY or SAMEORIGIN values only',
                owasp_reference='OWASP ASVS V14.4.2'
            )
        else:
            checks['x_frame_options'] = HeaderCheck(
                header='X-Frame-Options',
                present=False,
                value=None,
                severity=Severity.MEDIUM,
                description='Missing X-Frame-Options header - vulnerable to clickjacking',
                recommendation='Add X-Frame-Options: DENY or SAMEORIGIN',
                owasp_reference='OWASP ASVS V14.4.2'
            )
        
        # X-Content-Type-Options
        xcontent_header = headers.get('x-content-type-options')
        if xcontent_header:
            is_valid_xcontent = xcontent_header.lower().strip() == 'nosniff'
            severity = Severity.INFO if is_valid_xcontent else Severity.MEDIUM
            checks['x_content_type_options'] = HeaderCheck(
                header='X-Content-Type-Options',
                present=True,
                value=xcontent_header,
                severity=severity,
                description='X-Content-Type-Options prevents MIME-type sniffing',
                recommendation='Value should be "nosniff"',
                owasp_reference='OWASP ASVS V14.4.3'
            )
        else:
            checks['x_content_type_options'] = HeaderCheck(
                header='X-Content-Type-Options',
                present=False,
                value=None,
                severity=Severity.MEDIUM,
                description='Missing X-Content-Type-Options header - vulnerable to MIME sniffing',
                recommendation='Add X-Content-Type-Options: nosniff',
                owasp_reference='OWASP ASVS V14.4.3'
            )
        
        # Referrer-Policy
        referrer_header = headers.get('referrer-policy')
        if referrer_header:
            valid_policies = [
                'no-referrer', 'no-referrer-when-downgrade', 'origin',
                'origin-when-cross-origin', 'same-origin', 'strict-origin',
                'strict-origin-when-cross-origin', 'unsafe-url'
            ]
            is_valid_referrer = referrer_header.lower().strip() in valid_policies
            severity = Severity.INFO if is_valid_referrer else Severity.LOW
            checks['referrer_policy'] = HeaderCheck(
                header='Referrer-Policy',
                present=True,
                value=referrer_header,
                severity=severity,
                description='Referrer-Policy controls referrer information',
                recommendation='Use strict-origin-when-cross-origin or stricter',
                owasp_reference='OWASP ASVS V14.4.4'
            )
        else:
            checks['referrer_policy'] = HeaderCheck(
                header='Referrer-Policy',
                present=False,
                value=None,
                severity=Severity.LOW,
                description='Missing Referrer-Policy header',
                recommendation='Add Referrer-Policy: strict-origin-when-cross-origin',
                owasp_reference='OWASP ASVS V14.4.4'
            )
        
        # Permissions-Policy (formerly Feature-Policy)
        permissions_header = headers.get('permissions-policy')
        if permissions_header:
            checks['permissions_policy'] = HeaderCheck(
                header='Permissions-Policy',
                present=True,
                value=permissions_header,
                severity=Severity.INFO,
                description='Permissions-Policy controls browser features',
                recommendation='Review policy to ensure appropriate restrictions',
                owasp_reference='OWASP ASVS V14.4.5'
            )
        else:
            checks['permissions_policy'] = HeaderCheck(
                header='Permissions-Policy',
                present=False,
                value=None,
                severity=Severity.LOW,
                description='Missing Permissions-Policy header',
                recommendation='Consider adding Permissions-Policy for feature control',
                owasp_reference='OWASP ASVS V14.4.5'
            )
        
        return checks
    
    def _check_information_disclosure(self, headers: Dict[str, str]) -> Dict[str, HeaderCheck]:
        """Check for information disclosure in headers"""
        checks = {}
        
        # Server header
        server_header = headers.get('server')
        if server_header:
            # Check if server header reveals too much information
            reveals_version = self._check_version_disclosure(server_header)
            severity = Severity.LOW if not reveals_version else Severity.MEDIUM
            checks['server'] = HeaderCheck(
                header='Server',
                present=True,
                value=server_header,
                severity=severity,
                description='Server header may reveal sensitive information',
                recommendation='Remove or minimize server information disclosure',
                owasp_reference='OWASP ASVS V14.3.1'
            )
        else:
            checks['server'] = HeaderCheck(
                header='Server',
                present=False,
                value=None,
                severity=Severity.INFO,
                description='Server header not present (good for security)',
                recommendation='Keep server header removed or minimal',
                owasp_reference='OWASP ASVS V14.3.1'
            )
        
        # X-Powered-By header (should not be present)
        powered_by_header = headers.get('x-powered-by')
        if powered_by_header:
            checks['x_powered_by'] = HeaderCheck(
                header='X-Powered-By',
                present=True,
                value=powered_by_header,
                severity=Severity.MEDIUM,
                description='X-Powered-By header reveals technology stack',
                recommendation='Remove X-Powered-By header',
                owasp_reference='OWASP ASVS V14.3.2'
            )
        else:
            checks['x_powered_by'] = HeaderCheck(
                header='X-Powered-By',
                present=False,
                value=None,
                severity=Severity.INFO,
                description='X-Powered-By header not present (good)',
                recommendation='Keep X-Powered-By header removed',
                owasp_reference='OWASP ASVS V14.3.2'
            )
        
        return checks
    
    def _check_deprecated_headers(self, headers: Dict[str, str]) -> Dict[str, HeaderCheck]:
        """Check for deprecated security headers"""
        checks = {}
        
        # X-XSS-Protection (deprecated)
        xss_protection = headers.get('x-xss-protection')
        if xss_protection:
            checks['x_xss_protection'] = HeaderCheck(
                header='X-XSS-Protection',
                present=True,
                value=xss_protection,
                severity=Severity.LOW,
                description='X-XSS-Protection is deprecated',
                recommendation='Remove X-XSS-Protection and rely on CSP',
                owasp_reference='OWASP Top 10 A03:2021'
            )
        
        return checks
    
    def _validate_hsts(self, hsts_value: str) -> bool:
        """Validate HSTS header value"""
        hsts_lower = hsts_value.lower().strip()
        
        # Check for max-age directive
        max_age_match = re.search(r'max-age\s*=\s*(\d+)', hsts_lower)
        if not max_age_match:
            return False
        
        max_age = int(max_age_match.group(1))
        
        # Recommended minimum: 6 months (15552000 seconds)
        return max_age >= 15552000
    
    def _validate_csp(self, csp_value: str) -> bool:
        """Validate CSP header for basic security"""
        csp_lower = csp_value.lower().strip()
        
        # Check for dangerous directives
        dangerous_patterns = [
            r"'unsafe-inline'",
            r"'unsafe-eval'",
            r"\*",
            r"data:",
            r"blob:"
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, csp_lower):
                return False
        
        # Check for essential directives
        essential_directives = ['default-src', 'script-src']
        for directive in essential_directives:
            if directive not in csp_lower:
                return False
        
        return True
    
    def _check_version_disclosure(self, header_value: str) -> bool:
        """Check if header discloses version information"""
        version_patterns = [
            r'\d+\.\d+',  # Version numbers like 1.0, 2.4.1
            r'apache/\d+',
            r'nginx/\d+',
            r'php/\d+',
            r'microsoft-iis/\d+'
        ]
        
        header_lower = header_value.lower()
        for pattern in version_patterns:
            if re.search(pattern, header_lower):
                return True
        
        return False
    
    def generate_report(self, results: Dict[str, HeaderCheck], url: str) -> str:
        """Generate a comprehensive security report"""
        report = []
        report.append("=" * 80)
        report.append(f"OWASP SECURITY HEADERS SCAN REPORT")
        report.append("=" * 80)
        report.append(f"Target URL: {url}")
        report.append(f"Scan Date: {self._get_timestamp()}")
        report.append("=" * 80)
        report.append("")
        
        # Summary
        critical_count = sum(1 for check in results.values() if check.severity == Severity.CRITICAL)
        high_count = sum(1 for check in results.values() if check.severity == Severity.HIGH)
        medium_count = sum(1 for check in results.values() if check.severity == Severity.MEDIUM)
        low_count = sum(1 for check in results.values() if check.severity == Severity.LOW)
        
        report.append("SECURITY SUMMARY:")
        report.append(f"  Critical Issues: {critical_count}")
        report.append(f"  High Issues:     {high_count}")
        report.append(f"  Medium Issues:   {medium_count}")
        report.append(f"  Low Issues:      {low_count}")
        report.append("")
        
        # Detailed findings
        report.append("DETAILED FINDINGS:")
        report.append("-" * 50)
        
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            severity_results = [check for check in results.values() if check.severity == severity]
            if severity_results:
                report.append(f"\n{severity.value} SEVERITY:")
                for check in severity_results:
                    report.append(f"  [{check.severity.value}] {check.header}")
                    report.append(f"    Present: {check.present}")
                    if check.value:
                        report.append(f"    Value: {check.value}")
                    report.append(f"    Description: {check.description}")
                    report.append(f"    Recommendation: {check.recommendation}")
                    report.append(f"    OWASP Reference: {check.owasp_reference}")
                    report.append("")
        
        return "\n".join(report)
    
    def generate_colored_console_report(self, results: Dict[str, HeaderCheck], url: str) -> None:
        """Generate and display a colored console report as a justified table"""
        print()
        print(f"{Fore.CYAN + Style.BRIGHT}{'=' * 120}{Style.RESET_ALL}")
        print(f"{Fore.CYAN + Style.BRIGHT}OWASP SECURITY HEADERS SCAN REPORT{Style.RESET_ALL}")
        print(f"{Fore.CYAN + Style.BRIGHT}{'=' * 120}{Style.RESET_ALL}")
        print(f"{Fore.WHITE + Style.BRIGHT}Target URL:{Style.RESET_ALL} {Fore.YELLOW}{url}{Style.RESET_ALL}")
        print(f"{Fore.WHITE + Style.BRIGHT}Scan Date:{Style.RESET_ALL} {Fore.MAGENTA}{self._get_timestamp()}{Style.RESET_ALL}")
        print(f"{Fore.CYAN + Style.BRIGHT}{'=' * 120}{Style.RESET_ALL}")
        print()
        
        # Summary with colors
        critical_count = sum(1 for check in results.values() if check.severity == Severity.CRITICAL)
        high_count = sum(1 for check in results.values() if check.severity == Severity.HIGH)
        medium_count = sum(1 for check in results.values() if check.severity == Severity.MEDIUM)
        low_count = sum(1 for check in results.values() if check.severity == Severity.LOW)
        
        print(f"{Fore.WHITE + Style.BRIGHT}SECURITY SUMMARY:{Style.RESET_ALL}")
        print(f"  {Fore.RED + Style.BRIGHT}Critical Issues:{Style.RESET_ALL} {Fore.RED if critical_count > 0 else Fore.GREEN}{critical_count}{Style.RESET_ALL}")
        print(f"  {Fore.RED}High Issues:{Style.RESET_ALL}     {Fore.RED if high_count > 0 else Fore.GREEN}{high_count}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Medium Issues:{Style.RESET_ALL}   {Fore.YELLOW if medium_count > 0 else Fore.GREEN}{medium_count}{Style.RESET_ALL}")
        print(f"  {Fore.BLUE}Low Issues:{Style.RESET_ALL}      {Fore.BLUE if low_count > 0 else Fore.GREEN}{low_count}{Style.RESET_ALL}")
        print()
        
        # Detailed findings as justified table
        print(f"{Fore.WHITE + Style.BRIGHT}DETAILED FINDINGS:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─' * 120}{Style.RESET_ALL}")
        
        # Table header
        header_format = f"{{:<35}} {{:<10}} {{:<12}} {{:<60}}"
        print(f"{Fore.WHITE + Style.BRIGHT}{header_format.format('HEADER NAME', 'STATUS', 'SEVERITY', 'DESCRIPTION')}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─' * 120}{Style.RESET_ALL}")
        
        # Sort results by severity for better display
        sorted_results = sorted(results.values(), key=lambda x: [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO].index(x.severity))
        
        for check in sorted_results:
            # Truncate long values for table display
            status = "✓ Present" if check.present else "✗ Missing"
            status_colored = self._colorize_status(check.present)
            
            severity_colored = self._colorize_severity(check.severity)
            
            # Truncate description for table format
            description = check.description[:55] + "..." if len(check.description) > 58 else check.description
            
            # Print table row
            print(f"{Fore.WHITE + Style.BRIGHT}{check.header:<35}{Style.RESET_ALL} {status_colored:<20} {severity_colored:<22} {description}")
            
            # If there's a value, show it in the next line
            if check.value and len(check.value) <= 80:
                print(f"{'':<35} {Fore.CYAN}Value: {check.value[:75]}{'...' if len(check.value) > 75 else ''}{Style.RESET_ALL}")
            elif check.value:
                print(f"{'':<35} {Fore.CYAN}Value: [Too long to display - see text report]{Style.RESET_ALL}")
            
            print(f"{'':<35} {Fore.GREEN}Fix: {check.recommendation[:70]}{'...' if len(check.recommendation) > 70 else ''}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'─' * 120}{Style.RESET_ALL}")
        
        print()

    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")


def main():
    """Main function to run the header scanner"""
    if len(sys.argv) != 2:
        print(f"{Fore.RED}Usage:{Style.RESET_ALL} python header_scanner.py <URL>")
        print(f"{Fore.YELLOW}Example:{Style.RESET_ALL} python header_scanner.py https://example.com")
        sys.exit(1)
    
    url = sys.argv[1]
    scanner = OWASPHeaderScanner()
    
    print(f"{Fore.CYAN + Style.BRIGHT}🔍 OWASP Security Headers Scanner{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")
    
    # Scan the URL
    results = scanner.scan_url(url)
    
    if not results:
        print(f"{Fore.RED + Style.BRIGHT}❌ Scan failed. Please check the URL and try again.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Generate and display colored console report
    scanner.generate_colored_console_report(results, url)
    
    # Generate text report for file
    report = scanner.generate_report(results, url)
    
    # Save report to file
    report_filename = f"security_headers_report_{urlparse(url).netloc.replace('.', '_')}.txt"
    with open(report_filename, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"{Fore.CYAN}📄 Report saved to:{Style.RESET_ALL} {Fore.GREEN}{report_filename}{Style.RESET_ALL}")
    
    # Exit with appropriate code
    critical_issues = sum(1 for check in results.values() 
                         if check.severity in [Severity.CRITICAL, Severity.HIGH])
    
    if critical_issues > 0:
        print(f"\n{Fore.RED + Style.BRIGHT}⚠️  Found {critical_issues} critical/high severity issues!{Style.RESET_ALL}")
        sys.exit(1)
    else:
        print(f"\n{Fore.GREEN + Style.BRIGHT}✅ No critical security issues found!{Style.RESET_ALL}")
        sys.exit(0)


if __name__ == "__main__":
    main()