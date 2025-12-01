"""Base scanner interface for all security scanners"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime


class Severity(Enum):
    """Security issue severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ScanResult:
    """Standardized scan result format"""
    check_name: str
    status: str  # "pass", "fail", "warning", "info"
    severity: Severity
    message: str
    details: Optional[str] = None
    recommendation: Optional[str] = None
    reference: Optional[str] = None
    value: Optional[Any] = None


@dataclass
class ScannerReport:
    """Complete scanner report"""
    scanner_name: str
    scanner_version: str
    target_url: str
    scan_date: datetime
    duration: float  # seconds
    results: List[ScanResult]
    summary: Dict[str, int]  # {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 5}
    metadata: Dict[str, Any]  # Additional scanner-specific data
    
    def get_severity_counts(self) -> Dict[str, int]:
        """Count results by severity"""
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        for result in self.results:
            counts[result.severity.value] += 1
        return counts
    
    def has_critical_issues(self) -> bool:
        """Check if scan found critical issues"""
        return any(r.severity == Severity.CRITICAL and r.status == "fail" for r in self.results)
    
    def has_high_issues(self) -> bool:
        """Check if scan found high severity issues"""
        return any(r.severity == Severity.HIGH and r.status == "fail" for r in self.results)


class BaseScanner(ABC):
    """Base class for all security scanners"""
    
    def __init__(self, timeout: int = 30, user_agent: Optional[str] = None):
        self.timeout = timeout
        self.user_agent = user_agent or "SecurityScanner/1.0"
        self.version = "1.0.0"
    
    @abstractmethod
    async def scan(self, url: str) -> ScannerReport:
        """
        Perform security scan on target URL
        
        Args:
            url: Target URL to scan
            
        Returns:
            ScannerReport with scan results
        """
        pass
    
    @abstractmethod
    def get_scanner_info(self) -> Dict[str, Any]:
        """
        Get scanner metadata
        
        Returns:
            Dictionary with scanner name, description, version, etc.
        """
        pass
    
    def normalize_url(self, url: str) -> str:
        """Ensure URL has proper scheme"""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url
    
    def create_result(
        self,
        check_name: str,
        status: str,
        severity: Severity,
        message: str,
        details: Optional[str] = None,
        recommendation: Optional[str] = None,
        reference: Optional[str] = None,
        value: Optional[Any] = None
    ) -> ScanResult:
        """Helper to create standardized scan results"""
        return ScanResult(
            check_name=check_name,
            status=status,
            severity=severity,
            message=message,
            details=details,
            recommendation=recommendation,
            reference=reference,
            value=value
        )
