from typing import List, Dict, Any

class GuardPlugin:
    """Base class for SiteMap Guard plugins."""
    
    name: str = "BasePlugin"
    severity: str = "info"
    
    async def run(self, target_url: str, live_targets: List[Dict], dns_info: Dict[str, Any]) -> List[Dict]:
        """
        Execute the plugin logic.
        
        Args:
            target_url: The base target URL being scanned.
            live_targets: List of target dicts that responded (have status code).
            dns_info: Dictionary containing DNS recon data.
            
        Returns:
            List of finding dictionaries matching the standard format:
            {"type": "plugin_finding", "severity": self.severity, "name": "...", "url": "...", "details": "..."}
        """
        raise NotImplementedError("Plugins must implement the run method")
