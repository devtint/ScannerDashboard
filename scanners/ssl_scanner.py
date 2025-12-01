"""SSL/TLS Certificate Scanner"""
import ssl
import socket
import httpx
from datetime import datetime, timedelta
from typing import Dict, Optional
from scanners.base_scanner import BaseScanner, ScannerReport, ScanResult, Severity


class SSLScanner(BaseScanner):
    """Analyzes SSL/TLS certificate configuration and security"""
    
    def __init__(self, timeout: int = 30, user_agent: Optional[str] = None):
        super().__init__(timeout, user_agent)
        self.scanner_name = "SSL/TLS Certificate Scanner"
    
    async def scan(self, url: str) -> ScannerReport:
        """Scan SSL/TLS configuration"""
        url = self.normalize_url(url)
        start_time = datetime.utcnow()
        results = []
        
        # Extract hostname and port
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        if parsed.scheme != 'https':
            results.append(self.create_result(
                "HTTPS",
                "fail",
                Severity.CRITICAL,
                "Website does not use HTTPS",
                recommendation="Enable HTTPS with a valid SSL/TLS certificate"
            ))
        else:
            try:
                # Get certificate info
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        version = ssock.version()
                
                # Check certificate expiration
                results.extend(self._check_expiration(cert))
                
                # Check protocol version
                results.extend(self._check_protocol_version(version))
                
                # Check cipher strength
                results.extend(self._check_cipher(cipher))
                
                # Check certificate issuer
                results.extend(self._check_issuer(cert))
                
                # Check subject alternative names
                results.extend(self._check_san(cert, hostname))
                
            except ssl.SSLError as e:
                results.append(self.create_result(
                    "SSL/TLS",
                    "fail",
                    Severity.HIGH,
                    "SSL/TLS error",
                    details=str(e),
                    recommendation="Fix SSL/TLS configuration issues"
                ))
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
    
    def _check_expiration(self, cert: Dict) -> list[ScanResult]:
        """Check certificate expiration"""
        results = []
        
        not_after = cert.get('notAfter')
        if not_after:
            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (expiry_date - datetime.utcnow()).days
            
            if days_until_expiry < 0:
                results.append(self.create_result(
                    "Certificate Expiration",
                    "fail",
                    Severity.CRITICAL,
                    "Certificate has expired",
                    value=f"Expired {abs(days_until_expiry)} days ago",
                    recommendation="Renew certificate immediately"
                ))
            elif days_until_expiry < 30:
                results.append(self.create_result(
                    "Certificate Expiration",
                    "warning",
                    Severity.HIGH,
                    f"Certificate expires soon ({days_until_expiry} days)",
                    value=not_after,
                    recommendation="Renew certificate before expiration"
                ))
            else:
                results.append(self.create_result(
                    "Certificate Expiration",
                    "pass",
                    Severity.INFO,
                    f"Certificate valid for {days_until_expiry} days",
                    value=not_after
                ))
        
        return results
    
    def _check_protocol_version(self, version: str) -> list[ScanResult]:
        """Check TLS protocol version"""
        results = []
        
        secure_versions = ['TLSv1.2', 'TLSv1.3']
        deprecated_versions = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
        
        if version in deprecated_versions:
            results.append(self.create_result(
                "TLS Protocol",
                "fail",
                Severity.HIGH,
                f"Using deprecated protocol: {version}",
                value=version,
                recommendation="Upgrade to TLS 1.2 or TLS 1.3"
            ))
        elif version in secure_versions:
            results.append(self.create_result(
                "TLS Protocol",
                "pass",
                Severity.INFO,
                f"Using secure protocol: {version}",
                value=version
            ))
        else:
            results.append(self.create_result(
                "TLS Protocol",
                "warning",
                Severity.MEDIUM,
                f"Unknown protocol version: {version}",
                value=version
            ))
        
        return results
    
    def _check_cipher(self, cipher: tuple) -> list[ScanResult]:
        """Check cipher suite strength"""
        results = []
        
        if cipher:
            cipher_name = cipher[0]
            protocol = cipher[1]
            bits = cipher[2]
            
            # Check for weak ciphers
            weak_patterns = ['DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'anon']
            is_weak = any(pattern in cipher_name.upper() for pattern in weak_patterns)
            
            if is_weak:
                results.append(self.create_result(
                    "Cipher Suite",
                    "fail",
                    Severity.HIGH,
                    f"Weak cipher detected: {cipher_name}",
                    value=f"{cipher_name} ({bits} bits)",
                    recommendation="Use strong cipher suites (AES-GCM, ChaCha20)"
                ))
            elif bits >= 128:
                results.append(self.create_result(
                    "Cipher Suite",
                    "pass",
                    Severity.INFO,
                    f"Strong cipher in use: {cipher_name}",
                    value=f"{cipher_name} ({bits} bits)"
                ))
            else:
                results.append(self.create_result(
                    "Cipher Suite",
                    "warning",
                    Severity.MEDIUM,
                    f"Cipher strength below 128 bits: {bits}",
                    value=cipher_name
                ))
        
        return results
    
    def _check_issuer(self, cert: Dict) -> list[ScanResult]:
        """Check certificate issuer"""
        results = []
        
        issuer = dict(x[0] for x in cert.get('issuer', []))
        org_name = issuer.get('organizationName', 'Unknown')
        
        # Check if self-signed
        subject = dict(x[0] for x in cert.get('subject', []))
        is_self_signed = issuer.get('commonName') == subject.get('commonName')
        
        if is_self_signed:
            results.append(self.create_result(
                "Certificate Issuer",
                "warning",
                Severity.MEDIUM,
                "Certificate is self-signed",
                value=org_name,
                recommendation="Use certificate from trusted CA"
            ))
        else:
            results.append(self.create_result(
                "Certificate Issuer",
                "pass",
                Severity.INFO,
                f"Certificate issued by: {org_name}",
                value=org_name
            ))
        
        return results
    
    def _check_san(self, cert: Dict, hostname: str) -> list[ScanResult]:
        """Check Subject Alternative Names"""
        results = []
        
        san = cert.get('subjectAltName', [])
        san_names = [name for type, name in san if type == 'DNS']
        
        if hostname in san_names or f'*.{".".join(hostname.split(".")[1:])}' in san_names:
            results.append(self.create_result(
                "Subject Alternative Name",
                "pass",
                Severity.INFO,
                "Hostname matches certificate SAN",
                value=', '.join(san_names[:3])
            ))
        else:
            results.append(self.create_result(
                "Subject Alternative Name",
                "warning",
                Severity.MEDIUM,
                "Hostname may not match certificate",
                value=', '.join(san_names[:3]) if san_names else "No SAN found"
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
            "description": "Analyzes SSL/TLS certificate and encryption configuration",
            "category": "Security",
            "checks": [
                "Certificate Expiration",
                "TLS Protocol Version",
                "Cipher Suite Strength",
                "Certificate Issuer",
                "Subject Alternative Names"
            ]
        }
