"""
Modules API — List and configure available plugins.
"""
from fastapi import APIRouter
from plugins import registry

router = APIRouter(tags=["modules"])


@router.get("/modules")
def list_modules():
    """List all available plugins with their metadata."""
    return registry.info_all()


@router.get("/modules/{module_name}")
def get_module(module_name: str):
    """Get info for a specific module."""
    plugin = registry.get(module_name)
    if not plugin:
        return {"error": "Module not found"}, 404
    return plugin.info()
