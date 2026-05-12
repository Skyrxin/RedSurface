"""
Settings API — Manage API keys and module configuration.
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import ModuleConfig, get_db

router = APIRouter(tags=["settings"])


class ApiKeyUpdate(BaseModel):
    """Request body for updating a module's API key."""
    api_key: str


class ModuleToggle(BaseModel):
    """Enable/disable a module."""
    enabled: bool


@router.get("/settings/modules")
async def list_module_configs(db: AsyncSession = Depends(get_db)):
    """List all module configurations (API keys and enabled status)."""
    result = await db.execute(select(ModuleConfig))
    configs = result.scalars().all()
    return [c.to_dict() for c in configs]


@router.put("/settings/modules/{module_name}/key")
async def set_api_key(module_name: str, body: ApiKeyUpdate, db: AsyncSession = Depends(get_db)):
    """Set or update an API key for a module."""
    result = await db.execute(
        select(ModuleConfig).filter(ModuleConfig.module_name == module_name)
    )
    config = result.scalars().first()

    if not config:
        config = ModuleConfig(module_name=module_name, api_key=body.api_key)
        db.add(config)
    else:
        config.api_key = body.api_key

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
async def delete_api_key(module_name: str, db: AsyncSession = Depends(get_db)):
    """Remove an API key for a module."""
    result = await db.execute(
        select(ModuleConfig).filter(ModuleConfig.module_name == module_name)
    )
    config = result.scalars().first()
    if not config:
        raise HTTPException(status_code=404, detail="Module config not found")

    config.api_key = None
    await db.commit()
    return {"detail": "API key removed"}
