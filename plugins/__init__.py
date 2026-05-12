"""
Plugin Registry — Discovers and manages all available plugins.
"""
from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from typing import Dict, List, Optional

from plugins.base import PluginBase, PluginCategory


class PluginRegistry:
    """Central registry for all RedSurface plugins."""

    def __init__(self):
        self._plugins: Dict[str, PluginBase] = {}

    def register(self, plugin: PluginBase):
        """Register a plugin instance."""
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> Optional[PluginBase]:
        """Get a plugin by name."""
        return self._plugins.get(name)

    def all(self) -> List[PluginBase]:
        """Return all registered plugins."""
        return list(self._plugins.values())

    def by_category(self, category: PluginCategory) -> List[PluginBase]:
        """Return plugins filtered by category."""
        return [p for p in self._plugins.values() if p.category == category]

    def enabled(self) -> List[PluginBase]:
        """Return only enabled plugins."""
        return [p for p in self._plugins.values() if p.enabled]

    def discover_plugins(self):
        """
        Auto-discover and register plugins from plugins/ subdirectories.

        Walks through plugins/discovery/, plugins/osint/, plugins/threat_intel/,
        plugins/internal/ and imports any module that defines a PluginBase subclass.
        """
        plugins_dir = Path(__file__).parent
        subdirs = ["discovery", "osint", "threat_intel", "internal"]

        for subdir in subdirs:
            package_path = plugins_dir / subdir
            if not package_path.exists():
                package_path.mkdir(parents=True, exist_ok=True)
                # Create __init__.py if missing
                init_file = package_path / "__init__.py"
                if not init_file.exists():
                    init_file.write_text("")
                continue

            package_name = f"plugins.{subdir}"

            for importer, module_name, is_pkg in pkgutil.iter_modules([str(package_path)]):
                if module_name.startswith("_"):
                    continue
                try:
                    module = importlib.import_module(f"{package_name}.{module_name}")
                    # Look for PluginBase subclasses in the module
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (
                            isinstance(attr, type)
                            and issubclass(attr, PluginBase)
                            and attr is not PluginBase
                        ):
                            instance = attr()
                            self.register(instance)
                except Exception as e:
                    print(f"[!] Failed to load plugin {package_name}.{module_name}: {e}")

    def info_all(self) -> list:
        """Return info dicts for all plugins."""
        return [p.info() for p in self._plugins.values()]


# Global registry singleton
registry = PluginRegistry()
