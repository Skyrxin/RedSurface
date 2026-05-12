"""
RedSurface Plugin System — Base class, result types, and plugin registry.
"""
from __future__ import annotations

import importlib
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class PluginCategory(str, Enum):
    DISCOVERY = "Discovery"
    OSINT = "OSINT"
    THREAT_INTEL = "Threat Intelligence"
    INTERNAL = "Internal"
    TOOL = "Tool Integration"


class ApiType(str, Enum):
    FREE = "Free API"
    TIERED = "Tiered API"
    PAID = "Paid API"
    COMMERCIAL = "Commercial API"
    INTERNAL = "Internal"
    TOOL = "Tool"


@dataclass
class PluginResult:
    """Standardized result from a plugin execution."""
    plugin_name: str
    result_type: str  # subdomain, email, ip, technology, vulnerability, etc.
    values: List[str] = field(default_factory=list)
    parent_values: List[Optional[str]] = field(default_factory=list)  # Parallel to values
    per_value_metadata: List[Dict[str, Any]] = field(default_factory=list)  # Parallel to values
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    success: bool = True


class PluginBase(ABC):
    """
    Abstract base class for all RedSurface plugins.

    Every plugin must subclass this and implement the `run` method.
    Plugins self-register by being placed in a plugins/ subdirectory.
    """

    # --- Plugin Metadata (override in subclasses) ---
    name: str = "Unnamed Plugin"
    description: str = ""
    category: PluginCategory = PluginCategory.INTERNAL
    api_type: ApiType = ApiType.INTERNAL
    requires_api_key: bool = False
    api_key_names: List[str] = []
    result_types: List[str] = []  # What types of results this plugin produces
    target_types: List[str] = ["domain"]  # What target types are supported
    website: str = ""

    def __init__(self):
        self.api_keys: Dict[str, str] = {}
        self.enabled: bool = True

    def configure(self, api_keys: Dict[str, str] = None, extra_config: Dict[str, Any] = None):
        """Configure the plugin with API keys and extra settings."""
        if api_keys:
            self.api_keys = api_keys
        if extra_config:
            for k, v in extra_config.items():
                setattr(self, k, v)

    def is_ready(self) -> bool:
        """Check if the plugin has all required API keys."""
        if not self.requires_api_key:
            return True
        return all(
            self.api_keys.get(key_name) for key_name in self.api_key_names
        )

    @abstractmethod
    async def run(self, target: str, config: Dict[str, Any] = None) -> PluginResult:
        """
        Execute the plugin against a target.

        Args:
            target: Target domain or IP.
            config: Optional runtime config overrides.

        Returns:
            PluginResult with findings.
        """
        ...

    def info(self) -> Dict[str, Any]:
        """Return plugin metadata as a dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "api_type": self.api_type.value,
            "requires_api_key": self.requires_api_key,
            "api_key_names": self.api_key_names,
            "result_types": self.result_types,
            "target_types": self.target_types,
            "website": self.website,
            "is_ready": self.is_ready(),
            "enabled": self.enabled,
        }
