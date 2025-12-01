"""CORS Policy Scanner"""
import httpx
from typing import Dict, Optional
from datetime import datetime
from scanners.base_scanner import BaseScanner, ScannerReport, ScanResult, Severity


class CORSScanner(BaseScanner):
    """Analyzes Cross-Origin Resource Sharing (CORS) policy"""
    
    def __init__(self, timeout: int = 30, user_agent: Optional[str] = None):
        super().__init__(timeout, user_agent)
        self.scanner_name = "CORS Policy Scanner"
    
    async def scan(self, url: str) -> ScannerReport:
        """Scan CORS policy"""
        url = self.normalize_url(url)
        start_time = datetime.utcnow()
        results = []
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                # Standard GET request
                response = await client.get(
                    url,
                    headers={"User-Agent": self.user_agent},
                    follow_redirects=True
                )
                
                # Check for CORS headers
                headers_lower = {k.lower(): v for k, v in response.headers.items()}
                results.extend(self._check_cors_headers(headers_lower))
                
                # Test with Origin header
                test_response = await client.get(
                    url,
                    headers={
                        "User-Agent": self.user_agent,
                        "Origin": "https://evil.com"
                    }
                )
                test_headers = {k.lower(): v for k, v in test_response.headers.items()}
                results.extend(self._check_cors_misconfiguration(test_headers))
                
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
            metadata={}
        )
    
    def _check_cors_headers(self, headers: Dict[str, str]) -> list[ScanResult]:
        """Check CORS headers presence and configuration"""
        results = []
        
        acao = headers.get("access-control-allow-origin")
        acac = headers.get("access-control-allow-credentials")
        acam = headers.get("access-control-allow-methods")
        acah = headers.get("access-control-allow-headers")
        
        if not acao:
            results.append(self.create_result(
                "CORS Configuration",
                "info",
                Severity.INFO,
                "No CORS headers found",
                details="Website does not explicitly allow cross-origin requests"
            ))
        else:
            # Check for wildcard with credentials
            if acao == "*" and acac == "true":
                results.append(self.create_result(
                    "Access-Control-Allow-Origin",
                    "fail",
                    Severity.CRITICAL,
                    "Dangerous CORS configuration: wildcard with credentials",
                    value=f"Origin: {acao}, Credentials: {acac}",
                    recommendation="Never use wildcard (*) with credentials=true",
                    reference="https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"
                ))
            elif acao == "*":
                results.append(self.create_result(
                    "Access-Control-Allow-Origin",
                    "warning",
                    Severity.MEDIUM,
                    "CORS allows all origins (wildcard)",
                    value=acao,
                    recommendation="Restrict to specific trusted origins if possible"
                ))
            else:
                results.append(self.create_result(
                    "Access-Control-Allow-Origin",
                    "pass",
                    Severity.INFO,
                    f"CORS configured with specific origin: {acao}",
                    value=acao
                ))
            
            # Check allowed methods
            if acam:
                dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
                allowed = [m.strip().upper() for m in acam.split(',')]
                found_dangerous = [m for m in dangerous_methods if m in allowed]
                
                if found_dangerous:
                    results.append(self.create_result(
                        "Access-Control-Allow-Methods",
                        "warning",
                        Severity.MEDIUM,
                        f"Potentially dangerous methods allowed: {', '.join(found_dangerous)}",
                        value=acam,
                        recommendation="Only allow necessary HTTP methods"
                    ))
                else:
                    results.append(self.create_result(
                        "Access-Control-Allow-Methods",
                        "pass",
                        Severity.INFO,
                        "CORS methods appear safe",
                        value=acam
                    ))
        
        return results
    
    def _check_cors_misconfiguration(self, headers: Dict[str, str]) -> list[ScanResult]:
        """Check for CORS misconfigurations using test origin"""
        results = []
        
        acao = headers.get("access-control-allow-origin")
        
        if acao == "https://evil.com":
            results.append(self.create_result(
                "CORS Misconfiguration",
                "fail",
                Severity.CRITICAL,
                "CORS reflects arbitrary origins",
                details="Server reflects the Origin header without validation",
                recommendation="Implement strict origin whitelist validation",
                reference="https://portswigger.net/web-security/cors"
            ))
        elif acao and "evil.com" in acao:
            results.append(self.create_result(
                "CORS Misconfiguration",
                "warning",
                Severity.HIGH,
                "Potential CORS origin validation issue",
                value=acao
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
            "description": "Analyzes CORS policy for security misconfigurations",
            "category": "Security",
            "checks": [
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Credentials",
                "Access-Control-Allow-Methods",
                "CORS Misconfiguration Detection"
            ]
        }
