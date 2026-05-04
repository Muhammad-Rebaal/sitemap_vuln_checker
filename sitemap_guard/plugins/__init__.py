"""
SiteMap Guard Plugin System
Dynamically loads and executes user-defined or built-in scanner plugins.
"""
import asyncio
import importlib.util
import os
import structlog
from pathlib import Path
from typing import List, Dict, Any, Type

from .base import GuardPlugin

logger = structlog.get_logger()

async def run_all_plugins(
    target_url: str,
    live_targets: List[Dict],
    dns_info: Dict[str, Any]
) -> List[Dict]:
    """Dynamically loads and runs all GuardPlugin subclasses in the plugins directory."""
    plugins_dir = Path(__file__).parent
    plugin_files = [f for f in plugins_dir.glob("*.py") if f.name not in ("__init__.py", "base.py")]
    
    loaded_plugins: List[GuardPlugin] = []
    
    for pf in plugin_files:
        module_name = f"sitemap_guard.plugins.{pf.stem}"
        spec = importlib.util.spec_from_file_location(module_name, pf)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(mod)
                # Find all classes that inherit from GuardPlugin (excluding GuardPlugin itself)
                for attr_name in dir(mod):
                    attr = getattr(mod, attr_name)
                    if isinstance(attr, type) and issubclass(attr, GuardPlugin) and attr is not GuardPlugin:
                        loaded_plugins.append(attr())
            except Exception as e:
                logger.warning("plugins.load_failed", file=pf.name, error=str(e))

    if not loaded_plugins:
        return []

    logger.info("plugins.start", count=len(loaded_plugins), plugins=[p.name for p in loaded_plugins])

    async def _run_safe(plugin: GuardPlugin) -> List[Dict]:
        try:
            return await plugin.run(target_url, live_targets, dns_info)
        except Exception as e:
            logger.error("plugins.execution_failed", plugin=plugin.name, error=str(e))
            return []

    results = await asyncio.gather(*[_run_safe(p) for p in loaded_plugins])
    
    all_findings = []
    for r in results:
        all_findings.extend(r)
        
    logger.info("plugins.complete", findings=len(all_findings))
    return all_findings
