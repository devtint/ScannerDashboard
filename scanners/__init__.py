"""Scanner module initialization - Register all scanners"""
from utils.scanner_registry import scanner_registry
from scanners.security_headers import SecurityHeadersScanner
from scanners.ssl_scanner import SSLScanner
from scanners.cookie_scanner import CookieScanner
from scanners.cors_scanner import CORSScanner
from scanners.robots_scanner import RobotsScanner

# Register all scanners
scanner_registry.register("security_headers", SecurityHeadersScanner)
scanner_registry.register("ssl_tls", SSLScanner)
scanner_registry.register("cookie_security", CookieScanner)
scanner_registry.register("cors_policy", CORSScanner)
scanner_registry.register("robots_sitemap", RobotsScanner)

__all__ = [
    'SecurityHeadersScanner',
    'SSLScanner',
    'CookieScanner',
    'CORSScanner',
    'RobotsScanner',
    'scanner_registry'
]
