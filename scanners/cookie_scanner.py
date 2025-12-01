"""Cookie Security Scanner"""
import httpx
from typing import Dict, Optional
from datetime import datetime
from scanners.base_scanner import BaseScanner, ScannerReport, ScanResult, Severity


class CookieScanner(BaseScanner):
    """Analyzes cookie security attributes"""
    
    def __init__(self, timeout: int = 30, user_agent: Optional[str] = None):
        super().__init__(timeout, user_agent)
        self.scanner_name = "Cookie Security Scanner"
    
    async def scan(self, url: str) -> ScannerReport:
        """Scan cookie security"""
        url = self.normalize_url(url)
        start_time = datetime.utcnow()
        results = []
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                response = await client.get(
                    url,
                    headers={"User-Agent": self.user_agent},
                    follow_redirects=True
                )
            
            cookies = response.cookies
            
            if not cookies:
                results.append(self.create_result(
                    "Cookies",
                    "info",
                    Severity.INFO,
                    "No cookies found",
                    details="Website does not set any cookies"
                ))
            else:
                for cookie in cookies.jar:
                    results.extend(self._check_cookie_security(cookie))
            
        except Exception as e:
            results.append(self.create_result(
                "Connection",
                "fail",
                Severity.HIGH,
                "Failed to connect",
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
            metadata={"total_cookies": len(cookies) if cookies else 0}
        )
    
    def _check_cookie_security(self, cookie) -> list[ScanResult]:
        """Check individual cookie security attributes"""
        results = []
        cookie_name = cookie.name
        
        # Check Secure flag
        if not cookie.secure:
            results.append(self.create_result(
                f"Cookie: {cookie_name} - Secure",
                "fail",
                Severity.HIGH,
                f"Cookie '{cookie_name}' missing Secure flag",
                recommendation="Add Secure flag to ensure cookie is only sent over HTTPS",
                reference="https://owasp.org/www-community/controls/SecureCookieAttribute"
            ))
        else:
            results.append(self.create_result(
                f"Cookie: {cookie_name} - Secure",
                "pass",
                Severity.INFO,
                f"Cookie '{cookie_name}' has Secure flag",
                value="Secure"
            ))
        
        # Check HttpOnly flag
        if not cookie.has_nonstandard_attr('HttpOnly') and not getattr(cookie, '_rest', {}).get('HttpOnly'):
            # Session cookies should be HttpOnly
            if 'session' in cookie_name.lower() or 'auth' in cookie_name.lower():
                results.append(self.create_result(
                    f"Cookie: {cookie_name} - HttpOnly",
                    "fail",
                    Severity.HIGH,
                    f"Cookie '{cookie_name}' missing HttpOnly flag",
                    recommendation="Add HttpOnly flag to prevent XSS attacks",
                    reference="https://owasp.org/www-community/HttpOnly"
                ))
            else:
                results.append(self.create_result(
                    f"Cookie: {cookie_name} - HttpOnly",
                    "warning",
                    Severity.MEDIUM,
                    f"Cookie '{cookie_name}' missing HttpOnly flag",
                    recommendation="Consider adding HttpOnly flag"
                ))
        else:
            results.append(self.create_result(
                f"Cookie: {cookie_name} - HttpOnly",
                "pass",
                Severity.INFO,
                f"Cookie '{cookie_name}' has HttpOnly flag",
                value="HttpOnly"
            ))
        
        # Check SameSite attribute
        samesite = getattr(cookie, '_rest', {}).get('SameSite', '').lower()
        if not samesite or samesite == 'none':
            results.append(self.create_result(
                f"Cookie: {cookie_name} - SameSite",
                "warning",
                Severity.MEDIUM,
                f"Cookie '{cookie_name}' missing or has weak SameSite attribute",
                value=samesite or "Not set",
                recommendation="Set SameSite to 'Strict' or 'Lax' to prevent CSRF",
                reference="https://owasp.org/www-community/SameSite"
            ))
        else:
            results.append(self.create_result(
                f"Cookie: {cookie_name} - SameSite",
                "pass",
                Severity.INFO,
                f"Cookie '{cookie_name}' has SameSite={samesite}",
                value=samesite
            ))
        
        # Check expiration
        if cookie.expires is None:
            results.append(self.create_result(
                f"Cookie: {cookie_name} - Expiration",
                "info",
                Severity.INFO,
                f"Cookie '{cookie_name}' is a session cookie",
                details="Expires when browser closes"
            ))
        
        return results
    
    def _calculate_summary(self, results: list[ScanResult]) -> Dict[str, int]:
        """Calculate severity summary"""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for result in results:
            summary[result.severity.value] += 1
        return summary
    
    def get_scanner_info(self) -> Dict:
        """Get scanner metadata"""
        return {
            "name": self.scanner_name,
            "version": self.version,
            "description": "Analyzes cookie security attributes (Secure, HttpOnly, SameSite)",
            "category": "Security",
            "checks": [
                "Secure Flag",
                "HttpOnly Flag",
                "SameSite Attribute",
                "Cookie Expiration"
            ]
        }
