"""Robots.txt and Sitemap Scanner"""
import httpx
from typing import Dict, Optional
from datetime import datetime
from urllib.parse import urljoin
from scanners.base_scanner import BaseScanner, ScannerReport, ScanResult, Severity


class RobotsScanner(BaseScanner):
    """Analyzes robots.txt and sitemap.xml files"""
    
    def __init__(self, timeout: int = 30, user_agent: Optional[str] = None):
        super().__init__(timeout, user_agent)
        self.scanner_name = "Robots & Sitemap Scanner"
    
    async def scan(self, url: str) -> ScannerReport:
        """Scan robots.txt and sitemap"""
        url = self.normalize_url(url)
        start_time = datetime.utcnow()
        results = []
        
        # Get base URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                # Check robots.txt
                results.extend(await self._check_robots_txt(client, base_url))
                
                # Check sitemap.xml
                results.extend(await self._check_sitemap(client, base_url))
                
        except Exception as e:
            results.append(self.create_result(
                "Connection",
                "fail",
                Severity.MEDIUM,
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
    
    async def _check_robots_txt(self, client, base_url: str) -> list[ScanResult]:
        """Check robots.txt file"""
        results = []
        robots_url = urljoin(base_url, '/robots.txt')
        
        try:
            response = await client.get(robots_url, headers={"User-Agent": self.user_agent})
            
            if response.status_code == 200:
                content = response.text
                lines = content.split('\n')
                
                # Check for sensitive paths
                sensitive_keywords = [
                    'admin', 'login', 'config', 'backup', 'private', 
                    'secret', 'internal', 'dev', 'test', 'staging'
                ]
                
                disallowed_paths = []
                for line in lines:
                    line_lower = line.lower().strip()
                    if line_lower.startswith('disallow:'):
                        path = line_lower.split(':', 1)[1].strip()
                        if path and path != '/':
                            disallowed_paths.append(path)
                            
                            # Check for sensitive paths
                            if any(keyword in path for keyword in sensitive_keywords):
                                results.append(self.create_result(
                                    "Robots.txt - Sensitive Path",
                                    "warning",
                                    Severity.LOW,
                                    f"Potentially sensitive path disclosed: {path}",
                                    recommendation="Avoid disclosing sensitive paths in robots.txt"
                                ))
                
                results.append(self.create_result(
                    "Robots.txt",
                    "pass",
                    Severity.INFO,
                    "robots.txt found",
                    details=f"Contains {len(disallowed_paths)} disallowed paths",
                    value=f"{len(lines)} lines"
                ))
                
            elif response.status_code == 404:
                results.append(self.create_result(
                    "Robots.txt",
                    "info",
                    Severity.INFO,
                    "robots.txt not found",
                    recommendation="Consider creating robots.txt for SEO control"
                ))
            else:
                results.append(self.create_result(
                    "Robots.txt",
                    "warning",
                    Severity.LOW,
                    f"robots.txt returned status {response.status_code}"
                ))
                
        except Exception as e:
            results.append(self.create_result(
                "Robots.txt",
                "info",
                Severity.INFO,
                "Could not check robots.txt",
                details=str(e)
            ))
        
        return results
    
    async def _check_sitemap(self, client, base_url: str) -> list[ScanResult]:
        """Check sitemap.xml file"""
        results = []
        sitemap_urls = [
            urljoin(base_url, '/sitemap.xml'),
            urljoin(base_url, '/sitemap_index.xml'),
            urljoin(base_url, '/sitemap.xml.gz')
        ]
        
        found = False
        for sitemap_url in sitemap_urls:
            try:
                response = await client.get(sitemap_url, headers={"User-Agent": self.user_agent})
                
                if response.status_code == 200:
                    found = True
                    content_type = response.headers.get('content-type', '').lower()
                    
                    # Count URLs if XML
                    url_count = 0
                    if 'xml' in content_type:
                        url_count = response.text.count('<url>')
                    
                    results.append(self.create_result(
                        "Sitemap",
                        "pass",
                        Severity.INFO,
                        f"Sitemap found at {sitemap_url.split('/')[-1]}",
                        value=f"{url_count} URLs" if url_count > 0 else "Present"
                    ))
                    break
                    
            except Exception:
                continue
        
        if not found:
            results.append(self.create_result(
                "Sitemap",
                "info",
                Severity.INFO,
                "No sitemap found",
                recommendation="Consider creating sitemap.xml for better SEO"
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
            "description": "Analyzes robots.txt and sitemap.xml for information disclosure and SEO",
            "category": "Information Gathering",
            "checks": [
                "Robots.txt Presence",
                "Sensitive Path Disclosure",
                "Sitemap Presence",
                "URL Enumeration"
            ]
        }
