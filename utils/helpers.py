"""Common utility functions"""
import re
from typing import Optional
from datetime import datetime, timedelta


def validate_url(url: str) -> bool:
    """Validate URL format"""
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return url_pattern.match(url) is not None


def sanitize_url(url: str) -> str:
    """Sanitize URL for safe storage"""
    url = url.strip()
    # Remove potentially dangerous characters
    url = re.sub(r'[^\w\-\./:?=&%]', '', url)
    return url


def format_duration(seconds: float) -> str:
    """Format duration in human-readable format"""
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    else:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.1f}s"


def parse_cron_expression(cron: str) -> Optional[datetime]:
    """Parse cron expression to next run time (simplified)"""
    # This is a placeholder - use croniter or APScheduler for production
    # For now, just return 1 hour from now
    return datetime.utcnow() + timedelta(hours=1)


def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    pattern = r'https?://([^/]+)'
    match = re.search(pattern, url)
    return match.group(1) if match else url


def calculate_security_score(summary: dict) -> int:
    """
    Calculate overall security score (0-100) based on severity counts
    Higher score = better security
    """
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    low = summary.get("low", 0)
    
    # Start with perfect score
    score = 100
    
    # Deduct points based on severity
    score -= critical * 25  # Critical issues are severe
    score -= high * 15
    score -= medium * 8
    score -= low * 3
    
    # Ensure score stays within 0-100
    return max(0, min(100, score))
