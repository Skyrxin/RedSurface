"""
Scan Engine — Bridges the web API to the plugin-based scan execution.
Manages scan lifecycle: creation, async execution, result persistence.
"""
import asyncio
import logging
import traceback
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy import select, insert
from app import database as db_module
from app.database import Scan, ScanResult, ScanStatus, ModuleConfig
from plugins import registry
from plugins.base import PluginBase, PluginResult, PluginCategory
from app.api.ws import manager

logger = logging.getLogger("redsurface")


class ScanEngine:
    """Orchestrates scans using the plugin system."""

    def __init__(self, max_concurrent_plugins: int = 10):
        self._running_tasks: Dict[int, asyncio.Task] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent_plugins)

    async def _get_session(self):
        """Get an async database session, initializing if needed."""
        if db_module.AsyncSessionLocal is None:
            await db_module.init_db()
        return db_module.AsyncSessionLocal()

    async def start_scan(self, scan_id: int):
        """
        Execute a scan asynchronously using enabled plugins.
        """
        db = await self._get_session()
        try:
            result = await db.execute(select(Scan).filter(Scan.id == scan_id))
            scan = result.scalars().first()
            if not scan:
                logger.error(f"Scan {scan_id} not found in database")
                return

            # Update status to running
            scan.status = ScanStatus.RUNNING.value
            scan.started_at = datetime.now(timezone.utc)
            await db.commit()
            logger.info(f"Scan {scan_id} started for target: {scan.target}")
            
            # Broadcast scan started
            await manager.broadcast_to_scan(scan_id, {
                "event": "scan_started",
                "status": scan.status,
                "target": scan.target
            })

            target = scan.target
            scan_config = scan.config or {}
            scan_config["scan_id"] = scan_id
            scan_config["target_type"] = scan.target_type
            enabled_modules = scan_config.get("modules", [])

            if enabled_modules:
                plugins = [p for p in registry.all() if p.name in enabled_modules and scan.target_type in p.target_types]
            else:
                plugins = [p for p in registry.enabled() if scan.target_type in p.target_types]

            # Load API keys
            module_configs_result = await db.execute(select(ModuleConfig))
            module_configs = module_configs_result.scalars().all()
            key_map = {mc.module_name: mc for mc in module_configs}
            
            for plugin in plugins:
                mc = key_map.get(plugin.name)
                if mc:
                    full_keys = {}
                    if mc.api_key and plugin.api_key_names:
                        full_keys[plugin.api_key_names[0]] = mc.api_key
                    extra = mc.extra_config or {}
                    for kn in plugin.api_key_names:
                        if kn in extra:
                            full_keys[kn] = extra[kn]
                    if full_keys:
                        plugin.configure(api_keys=full_keys)

            ready_plugins = [p for p in plugins if p.is_ready()]
            
            discovery_plugins = [p for p in ready_plugins if p.category == PluginCategory.DISCOVERY]
            internal_plugins = [p for p in ready_plugins if p.category == PluginCategory.INTERNAL]
            other_plugins = [p for p in ready_plugins if p.category not in [PluginCategory.DISCOVERY, PluginCategory.INTERNAL]]
            
            stages = [discovery_plugins, internal_plugins, other_plugins]
            
            total_values = 0
            for stage_idx, stage_plugins in enumerate(stages):
                if not stage_plugins:
                    continue
                
                logger.info(f"Scan {scan_id}: Starting Stage {stage_idx + 1}")
                await manager.broadcast_to_scan(scan_id, {
                    "event": "stage_started",
                    "stage": stage_idx + 1,
                    "plugins": [p.name for p in stage_plugins]
                })
                
                tasks = [self._run_plugin(plugin, target, scan_config) for plugin in stage_plugins]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                bulk_results = []
                for result in results:
                    if isinstance(result, Exception):
                        bulk_results.append({
                            "scan_id": scan_id, "module_name": "error", "result_type": "error",
                            "value": str(result), "parent_value": None, "metadata_json": {}
                        })
                        continue
                    if isinstance(result, PluginResult):
                        total_values += len(result.values)
                        for idx, value in enumerate(result.values):
                            parent_value = result.parent_values[idx] if (result.parent_values and idx < len(result.parent_values)) else None
                            metadata = result.per_value_metadata[idx] if (result.per_value_metadata and idx < len(result.per_value_metadata)) else (result.metadata or {})
                            
                            bulk_results.append({
                                "scan_id": scan_id,
                                "module_name": result.plugin_name,
                                "result_type": result.result_type,
                                "value": value,
                                "parent_value": parent_value,
                                "metadata_json": metadata,
                            })
                        if result.errors:
                            for err in result.errors:
                                bulk_results.append({
                                    "scan_id": scan_id, "module_name": result.plugin_name, "result_type": "error",
                                    "value": err, "parent_value": None, "metadata_json": {}
                                })
                
                if bulk_results:
                    # ENSURE ALL DICTS HAVE IDENTICAL KEYS FOR BULK INSERT
                    await db.execute(insert(ScanResult).values(bulk_results))
                await db.commit()
                
                if bulk_results:
                    await manager.broadcast_to_scan(scan_id, {"event": "results_found", "results": bulk_results})

            # Mark completed
            result = await db.execute(select(Scan).filter(Scan.id == scan_id))
            scan = result.scalars().first()
            scan.status = ScanStatus.COMPLETED.value
            scan.completed_at = datetime.now(timezone.utc)
            if scan.started_at:
                started = scan.started_at.replace(tzinfo=timezone.utc) if scan.started_at.tzinfo is None else scan.started_at
                scan.duration_seconds = (scan.completed_at - started).total_seconds()
            await db.commit()
            
            await manager.broadcast_to_scan(scan_id, {
                "event": "scan_completed", "status": scan.status, "duration": scan.duration_seconds, "total_results": total_values
            })

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}\n{traceback.format_exc()}")
            try:
                result = await db.execute(select(Scan).filter(Scan.id == scan_id))
                scan = result.scalars().first()
                if scan:
                    scan.status = ScanStatus.FAILED.value
                    scan.error_message = str(e)
                    scan.completed_at = datetime.now(timezone.utc)
                    await db.commit()
                    await manager.broadcast_to_scan(scan_id, {"event": "scan_failed", "status": scan.status, "error": str(e)})
            except: pass
        finally:
            await db.close()

    async def _run_plugin(self, plugin: PluginBase, target: str, config: dict) -> PluginResult:
        async with self._semaphore:
            try:
                return await asyncio.wait_for(plugin.run(target, config), timeout=config.get("timeout", 120))
            except Exception as e:
                return PluginResult(plugin_name=plugin.name, result_type="error", success=False, errors=[str(e)])

    def launch_scan(self, scan_id: int):
        task = asyncio.create_task(self.start_scan(scan_id))
        self._running_tasks[scan_id] = task
        task.add_done_callback(lambda t: self._running_tasks.pop(scan_id, None))
        return task

    def cancel_scan(self, scan_id: int) -> bool:
        task = self._running_tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
            return True
        return False

scan_engine = ScanEngine(max_concurrent_plugins=10)
