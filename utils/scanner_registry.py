"""Scanner registry and management"""
from typing import Dict, List, Type
from scanners.base_scanner import BaseScanner


class ScannerRegistry:
    """Central registry for all security scanners"""
    
    def __init__(self):
        self._scanners: Dict[str, Type[BaseScanner]] = {}
    
    def register(self, name: str, scanner_class: Type[BaseScanner]):
        """Register a scanner"""
        self._scanners[name] = scanner_class
    
    def get_scanner(self, name: str, **kwargs) -> BaseScanner:
        """Get scanner instance by name"""
        if name not in self._scanners:
            raise ValueError(f"Scanner '{name}' not found")
        return self._scanners[name](**kwargs)
    
    def list_scanners(self) -> List[str]:
        """List all registered scanner names"""
        return list(self._scanners.keys())
    
    def get_all_scanner_info(self) -> List[Dict]:
        """Get info for all scanners"""
        return [
            self.get_scanner(name).get_scanner_info()
            for name in self.list_scanners()
        ]


# Global scanner registry
scanner_registry = ScannerRegistry()
