"""Security Headers Scanner - OWASP Compliant"""
import httpx
import re
from typing import Dict, Optional
from datetime import datetime
from scanners.base_scanner import BaseScanner, ScannerReport, ScanResult, Severity


class SecurityHeadersScanner(BaseScanner):
    """
    Scans HTTP security headers according to OWASP guidelines
    Performs case-insensitive header detection for accuracy
    """
    
    def __init__(self, timeout: int = 30, user_agent: Optional[str] = None):
        super().__init__(timeout, user_agent)
        self.scanner_name = "Security Headers Scanner"
    
    async def scan(self, url: str) -> ScannerReport:
        """Scan security headers of target URL"""
        url = self.normalize_url(url)
        start_time = datetime.utcnow()
        results = []
        
        try:
            # Make HTTP request
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                response = await client.get(
                    url,
                    headers={"User-Agent": self.user_agent},
                    follow_redirects=True
                )
            
            # Convert headers to lowercase for case-insensitive checks
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            
            # Check security headers
            results.extend(self._check_hsts(headers_lower))
            results.extend(self._check_csp(headers_lower))
            results.extend(self._check_x_frame_options(headers_lower))
            results.extend(self._check_x_content_type_options(headers_lower))
            results.extend(self._check_referrer_policy(headers_lower))
            results.extend(self._check_permissions_policy(headers_lower))
            
            # Check information disclosure
            results.extend(self._check_server_header(headers_lower))
            results.extend(self._check_x_powered_by(headers_lower))
            
            # Check deprecated headers
            results.extend(self._check_deprecated_headers(headers_lower))
            
        except httpx.TimeoutException:
            results.append(self.create_result(
                "Connection",
                "fail",
                Severity.HIGH,
                "Request timeout",
                details=f"Failed to connect to {url} within {self.timeout} seconds"
            ))
        except Exception as e:
            results.append(self.create_result(
                "Connection",
                "fail",
                Severity.HIGH,
                "Connection error",
                details=str(e)
            ))
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        return ScannerReport(
            scanner_name=self.scanner_name,
            scanner_version=self.version,
            target_url=url,
            scan_date=start_time,
            duration=duration,
            results=results,
            summary=self._calculate_summary(results),
            metadata={"total_headers_checked": len(results)}
        )
    
    def _check_hsts(self, headers: Dict[str, str]) -> list[ScanResult]:
        """Check Strict-Transport-Security header"""
        results = []
        header_value = headers.get("strict-transport-security")
        
        if not header_value:
            results.append(self.create_result(
                "Strict-Transport-Security",
                "fail",
                Severity.HIGH,
                "HSTS header is missing",
                recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
                reference="https://owasp.org/www-project-secure-headers/#strict-transport-security"
            ))
        else:
            # Validate HSTS configuration
            max_age_match = re.search(r'max-age=(\d+)', header_value.lower())
            if not max_age_match:
                results.append(self.create_result(
                    "Strict-Transport-Security",
                    "fail",
                    Severity.HIGH,
                    "HSTS header present but missing max-age directive",
                    value=header_value,
                    recommendation="Ensure max-age is at least 15552000 (6 months)"
                ))
            else:
                max_age = int(max_age_match.group(1))
                if max_age < 15552000:  # 6 months minimum
                    results.append(self.create_result(
                        "Strict-Transport-Security",
                        "warning",
                        Severity.MEDIUM,
                        f"HSTS max-age is too short: {max_age} seconds",
                        value=header_value,
                        recommendation="Increase max-age to at least 15552000 (6 months)"
                    ))
                else:
                    results.append(self.create_result(
                        "Strict-Transport-Security",
                        "pass",
                        Severity.INFO,
                        "HSTS properly configured",
                        value=header_value
                    ))
        
        return results
    
    def _check_csp(self, headers: Dict[str, str]) -> list[ScanResult]:
        """Check Content-Security-Policy header"""
        results = []
        header_value = headers.get("content-security-policy")
        
        if not header_value:
            results.append(self.create_result(
                "Content-Security-Policy",
                "fail",
                Severity.HIGH,
                "CSP header is missing",
                recommendation="Implement a Content Security Policy to prevent XSS attacks",
                reference="https://owasp.org/www-project-secure-headers/#content-security-policy"
            ))
        else:
            # Check for unsafe directives
            unsafe_patterns = ["unsafe-inline", "unsafe-eval", "unsafe-hashes"]
            found_unsafe = [p for p in unsafe_patterns if p in header_value.lower()]
            
            if found_unsafe:
                results.append(self.create_result(
                    "Content-Security-Policy",
                    "warning",
                    Severity.MEDIUM,
                    f"CSP contains unsafe directives: {', '.join(found_unsafe)}",
                    value=header_value,
                    recommendation="Remove unsafe directives and use nonces or hashes instead"
                ))
            else:
                results.append(self.create_result(
                    "Content-Security-Policy",
                    "pass",
                    Severity.INFO,
                    "CSP header present and properly configured",
                    value=header_value
                ))
        
        return results
    
    def _check_x_frame_options(self, headers: Dict[str, str]) -> list[ScanResult]:
        """Check X-Frame-Options header"""
        results = []
        header_value = headers.get("x-frame-options")
        
        if not header_value:
            results.append(self.create_result(
                "X-Frame-Options",
                "fail",
                Severity.MEDIUM,
                "X-Frame-Options header is missing",
                recommendation="Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'",
                reference="https://owasp.org/www-project-secure-headers/#x-frame-options"
            ))
        else:
            valid_values = ["deny", "sameorigin"]
            if header_value.lower() in valid_values:
                results.append(self.create_result(
                    "X-Frame-Options",
                    "pass",
                    Severity.INFO,
                    "X-Frame-Options properly configured",
                    value=header_value
                ))
            else:
                results.append(self.create_result(
                    "X-Frame-Options",
                    "warning",
                    Severity.MEDIUM,
                    f"X-Frame-Options has unexpected value: {header_value}",
                    value=header_value,
                    recommendation="Use 'DENY' or 'SAMEORIGIN'"
                ))
        
        return results
    
    def _check_x_content_type_options(self, headers: Dict[str, str]) -> list[ScanResult]:
        """Check X-Content-Type-Options header"""
        results = []
        header_value = headers.get("x-content-type-options")
        
        if not header_value:
            results.append(self.create_result(
                "X-Content-Type-Options",
                "fail",
                Severity.MEDIUM,
                "X-Content-Type-Options header is missing",
                recommendation="Add 'X-Content-Type-Options: nosniff'",
                reference="https://owasp.org/www-project-secure-headers/#x-content-type-options"
            ))
        else:
            if header_value.lower() == "nosniff":
                results.append(self.create_result(
                    "X-Content-Type-Options",
                    "pass",
                    Severity.INFO,
                    "X-Content-Type-Options properly configured",
                    value=header_value
                ))
            else:
                results.append(self.create_result(
                    "X-Content-Type-Options",
                    "warning",
                    Severity.MEDIUM,
                    f"Unexpected value: {header_value}",
                    value=header_value,
                    recommendation="Use 'nosniff'"
                ))
        
        return results
    
    def _check_referrer_policy(self, headers: Dict[str, str]) -> list[ScanResult]:
        """Check Referrer-Policy header"""
        results = []
        header_value = headers.get("referrer-policy")
        
        if not header_value:
            results.append(self.create_result(
                "Referrer-Policy",
                "warning",
                Severity.LOW,
                "Referrer-Policy header is missing",
                recommendation="Add 'Referrer-Policy: no-referrer' or 'strict-origin-when-cross-origin'",
                reference="https://owasp.org/www-project-secure-headers/#referrer-policy"
            ))
        else:
            secure_values = ["no-referrer", "no-referrer-when-downgrade", "strict-origin", 
                           "strict-origin-when-cross-origin", "same-origin"]
            if header_value.lower() in secure_values:
                results.append(self.create_result(
                    "Referrer-Policy",
                    "pass",
                    Severity.INFO,
                    "Referrer-Policy properly configured",
                    value=header_value
                ))
            else:
                results.append(self.create_result(
                    "Referrer-Policy",
                    "warning",
                    Severity.LOW,
                    f"Referrer-Policy may be insecure: {header_value}",
                    value=header_value
                ))
        
        return results
    
    def _check_permissions_policy(self, headers: Dict[str, str]) -> list[ScanResult]:
        """Check Permissions-Policy header"""
        results = []
        header_value = headers.get("permissions-policy")
        
        if not header_value:
            results.append(self.create_result(
                "Permissions-Policy",
                "info",
                Severity.LOW,
                "Permissions-Policy header is missing (optional)",
                recommendation="Consider adding Permissions-Policy to restrict browser features",
                reference="https://owasp.org/www-project-secure-headers/#permissions-policy"
            ))
        else:
            results.append(self.create_result(
                "Permissions-Policy",
                "pass",
                Severity.INFO,
                "Permissions-Policy is configured",
                value=header_value
            ))
        
        return results
    
    def _check_server_header(self, headers: Dict[str, str]) -> list[ScanResult]:
        """Check for Server header information disclosure"""
        results = []
        header_value = headers.get("server")
        
        if header_value:
            # Check for version numbers
            version_pattern = r'\d+\.\d+'
            if re.search(version_pattern, header_value):
                results.append(self.create_result(
                    "Server",
                    "warning",
                    Severity.LOW,
                    "Server header discloses version information",
                    value=header_value,
                    recommendation="Remove or obfuscate server version information"
                ))
            else:
                results.append(self.create_result(
                    "Server",
                    "info",
                    Severity.INFO,
                    "Server header present without version info",
                    value=header_value
                ))
        else:
            results.append(self.create_result(
                "Server",
                "pass",
                Severity.INFO,
                "Server header is not disclosed (good practice)",
                details="Not revealing server information improves security through obscurity"
            ))
        
        return results
    
    def _check_x_powered_by(self, headers: Dict[str, str]) -> list[ScanResult]:
        """Check for X-Powered-By header"""
        results = []
        header_value = headers.get("x-powered-by")
        
        if header_value:
            results.append(self.create_result(
                "X-Powered-By",
                "warning",
                Severity.LOW,
                "X-Powered-By header discloses technology stack",
                value=header_value,
                recommendation="Remove X-Powered-By header to prevent information disclosure"
            ))
        else:
            results.append(self.create_result(
                "X-Powered-By",
                "pass",
                Severity.INFO,
                "X-Powered-By header is not disclosed (good practice)"
            ))
        
        return results
    
    def _check_deprecated_headers(self, headers: Dict[str, str]) -> list[ScanResult]:
        """Check for deprecated security headers"""
        results = []
        
        # X-XSS-Protection is deprecated
        if "x-xss-protection" in headers:
            results.append(self.create_result(
                "X-XSS-Protection",
                "warning",
                Severity.LOW,
                "X-XSS-Protection is deprecated",
                value=headers["x-xss-protection"],
                recommendation="Remove X-XSS-Protection and use Content-Security-Policy instead",
                reference="https://owasp.org/www-project-secure-headers/"
            ))
        
        return results
    
    def _calculate_summary(self, results: list[ScanResult]) -> Dict[str, int]:
        """Calculate severity summary"""
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        for result in results:
            summary[result.severity.value] += 1
        return summary
    
    def get_scanner_info(self) -> Dict:
        """Get scanner metadata"""
        return {
            "name": self.scanner_name,
            "version": self.version,
            "description": "Scans HTTP security headers according to OWASP guidelines",
            "category": "Security",
            "checks": [
                "Strict-Transport-Security (HSTS)",
                "Content-Security-Policy (CSP)",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
                "Permissions-Policy",
                "Server Information Disclosure",
                "X-Powered-By",
                "Deprecated Headers"
            ]
        }
