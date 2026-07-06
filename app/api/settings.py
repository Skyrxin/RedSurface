"""
Settings API — Manage API keys and module configuration.
"""
from typing import Optional, List, Dict
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import ModuleConfig, get_db

router = APIRouter(tags=["settings"])


class ApiKeyUpdate(BaseModel):
    """Request body for updating a module's API key."""
    key_name: Optional[str] = "api_key"  # Default for single-key modules
    key_value: str


class ModuleToggle(BaseModel):
    """Enable/disable a module."""
    enabled: bool


@router.get("/settings/modules")
async def list_module_configs(db: AsyncSession = Depends(get_db)):
    """List all module configurations (API keys and enabled status)."""
    result = await db.execute(select(ModuleConfig))
    configs = result.scalars().all()
    
    final_configs = []
    for c in configs:
        d = c.to_dict()
        # Merge all keys into a single 'keys' dict for the UI
        keys = {}
        if c.api_key:
            keys["api_key"] = True
        
        extra = c.extra_config or {}
        for k, v in extra.items():
            # Basic heuristic for what constitutes a "key" in extra_config
            if k.endswith("_key") or k.endswith("_id") or k.endswith("_secret") or k.endswith("_token") or k == "intelx" or k == "serpapi" or k == "google_search_cx":
                keys[k] = True
                
        d["keys"] = keys
        final_configs.append(d)
        
    return final_configs


@router.put("/settings/modules/{module_name}/key")
async def set_api_key(module_name: str, body: ApiKeyUpdate, db: AsyncSession = Depends(get_db)):
    """Set or update an API key for a module. Supports multiple keys via extra_config."""
    result = await db.execute(
        select(ModuleConfig).filter(ModuleConfig.module_name == module_name)
    )
    config = result.scalars().first()

    if not config:
        config = ModuleConfig(module_name=module_name)
        db.add(config)

    # If it's the primary key (default), use the main column
    if body.key_name == "api_key":
        config.api_key = body.key_value
    else:
        # Store in extra_config
        extra = config.extra_config or {}
        extra[body.key_name] = body.key_value
        config.extra_config = extra

    await db.commit()
    await db.refresh(config)
    return config.to_dict()


@router.put("/settings/modules/{module_name}/toggle")
async def toggle_module(module_name: str, body: ModuleToggle, db: AsyncSession = Depends(get_db)):
    """Enable or disable a module."""
    result = await db.execute(
        select(ModuleConfig).filter(ModuleConfig.module_name == module_name)
    )
    config = result.scalars().first()

    if not config:
        config = ModuleConfig(module_name=module_name, enabled=body.enabled)
        db.add(config)
    else:
        config.enabled = body.enabled

    await db.commit()
    await db.refresh(config)
    return config.to_dict()


@router.delete("/settings/modules/{module_name}/key")
async def delete_api_key(module_name: str, key_name: str = "api_key", db: AsyncSession = Depends(get_db)):
    """Remove a specific API key for a module."""
    result = await db.execute(
        select(ModuleConfig).filter(ModuleConfig.module_name == module_name)
    )
    config = result.scalars().first()
    if not config:
        raise HTTPException(status_code=404, detail="Module config not found")

    if key_name == "api_key":
        config.api_key = None
    else:
        extra = config.extra_config or {}
        if key_name in extra:
            del extra[key_name]
            config.extra_config = extra

    await db.commit()
    return {"detail": f"Key '{key_name}' removed"}
