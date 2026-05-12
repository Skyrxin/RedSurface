"""
Scan Engine — Bridges the web API to the plugin-based scan execution.
Manages scan lifecycle: creation, async execution, result persistence.
"""
import asyncio
import logging
import traceback
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy import select
from app import database as db_module
from app.database import Scan, ScanResult, ScanStatus, ModuleConfig, AsyncSessionLocal
from plugins import registry
from plugins.base import PluginBase, PluginResult, PluginCategory

logger = logging.getLogger("redsurface")


class ScanEngine:
    """Orchestrates scans using the plugin system."""

    def __init__(self):
        self._running_tasks: Dict[int, asyncio.Task] = {}

    async def _get_session(self):
        """Get an async database session, initializing if needed."""
        if db_module.AsyncSessionLocal is None:
            await db_module.init_db()
        return db_module.AsyncSessionLocal()

    async def start_scan(self, scan_id: int):
        """
        Execute a scan asynchronously using enabled plugins.

        Args:
            scan_id: Database ID of the scan to execute.
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

            target = scan.target
            scan_config = scan.config or {}
            scan_config["scan_id"] = scan_id  # Pass scan_id for plugins that need context
            scan_config["target_type"] = scan.target_type  # Inject target type for dynamic plugins
            enabled_modules = scan_config.get("modules", [])

            # Get all plugins (or only selected ones) that support this target type
            if enabled_modules:
                plugins = [p for p in registry.all() if p.name in enabled_modules and scan.target_type in p.target_types]
            else:
                plugins = [p for p in registry.enabled() if scan.target_type in p.target_types]

            logger.info(f"Scan {scan_id}: {len(plugins)} plugins loaded")

            # Load API keys from DB into plugins
            module_configs_result = await db.execute(select(ModuleConfig))
            module_configs = module_configs_result.scalars().all()
            key_map = {mc.module_name: mc for mc in module_configs}
            for plugin in plugins:
                mc = key_map.get(plugin.name)
                if mc and mc.api_key:
                    keys = {kn: mc.api_key for kn in plugin.api_key_names}
                    plugin.configure(api_keys=keys)

            # Filter to only ready plugins
            ready_plugins = [p for p in plugins if p.is_ready()]
            logger.info(
                f"Scan {scan_id}: {len(ready_plugins)} plugins ready "
                f"(skipped {len(plugins) - len(ready_plugins)} needing API keys)"
            )

            # Group plugins by stage
            discovery_plugins = [p for p in ready_plugins if p.category == PluginCategory.DISCOVERY]
            internal_plugins = [p for p in ready_plugins if p.category == PluginCategory.INTERNAL]
            other_plugins = [p for p in ready_plugins if p.category not in [PluginCategory.DISCOVERY, PluginCategory.INTERNAL]]
            
            stages = [discovery_plugins, internal_plugins, other_plugins]
            
            total_values = 0
            for stage_idx, stage_plugins in enumerate(stages):
                if not stage_plugins:
                    continue
                
                logger.info(f"Scan {scan_id}: Starting Stage {stage_idx + 1} ({len(stage_plugins)} plugins)")
                
                tasks = []
                for plugin in stage_plugins:
                    tasks.append(self._run_plugin(plugin, target, scan_config))

                results = await asyncio.gather(*tasks, return_exceptions=True)

                # Save results to DB after each stage so next stage can read them
                for result in results:
                    if isinstance(result, Exception):
                        logger.error(f"Scan {scan_id}: plugin exception: {result}")
                        db.add(ScanResult(
                            scan_id=scan_id,
                            module_name="error",
                            result_type="error",
                            value=str(result),
                        ))
                        continue
                    if isinstance(result, PluginResult):
                        total_values += len(result.values)
                        for idx, value in enumerate(result.values):
                            parent_value = None
                            if result.parent_values and idx < len(result.parent_values):
                                parent_value = result.parent_values[idx]
                            
                            # Use per-value metadata if provided, otherwise fallback to global metadata
                            metadata = result.metadata
                            if result.per_value_metadata and idx < len(result.per_value_metadata):
                                metadata = result.per_value_metadata[idx]
                            
                            db.add(ScanResult(
                                scan_id=scan_id,
                                module_name=result.plugin_name,
                                result_type=result.result_type,
                                value=value,
                                parent_value=parent_value,
                                metadata_json=metadata,
                            ))
                        if result.errors:
                            for err in result.errors:
                                logger.warning(f"Scan {scan_id}: {result.plugin_name}: {err}")
                                db.add(ScanResult(
                                    scan_id=scan_id,
                                    module_name=result.plugin_name,
                                    result_type="error",
                                    value=err,
                                ))
                await db.commit() # Commit after each stage

            # Mark scan as completed
            # Re-fetch scan to avoid session issues if it was closed or expired
            result = await db.execute(select(Scan).filter(Scan.id == scan_id))
            scan = result.scalars().first()
            
            scan.status = ScanStatus.COMPLETED.value
            scan.completed_at = datetime.now(timezone.utc)
            if scan.started_at:
                # Ensure both are timezone-aware for subtraction
                completed = scan.completed_at
                started = scan.started_at
                if started.tzinfo is None:
                    started = started.replace(tzinfo=timezone.utc)
                if completed.tzinfo is None:
                    completed = completed.replace(tzinfo=timezone.utc)
                scan.duration_seconds = (completed - started).total_seconds()
            await db.commit()
            logger.info(
                f"Scan {scan_id} completed: {total_values} results "
                f"in {scan.duration_seconds:.1f}s"
            )

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}\n{traceback.format_exc()}")
            try:
                # Re-fetch to be safe
                result = await db.execute(select(Scan).filter(Scan.id == scan_id))
                scan = result.scalars().first()
                if scan:
                    scan.status = ScanStatus.FAILED.value
                    scan.error_message = traceback.format_exc()
                    scan.completed_at = datetime.now(timezone.utc)
                    await db.commit()
            except Exception:
                pass
        finally:
            await db.close()

    async def _run_plugin(
        self, plugin: PluginBase, target: str, config: dict
    ) -> PluginResult:
        """Run a single plugin with error handling."""
        logger.info(f"Running plugin: {plugin.name}")
        try:
            result = await asyncio.wait_for(
                plugin.run(target, config),
                timeout=config.get("timeout", 120),
            )
            logger.info(
                f"Plugin {plugin.name}: {len(result.values)} results"
                + (f", errors: {result.errors}" if result.errors else "")
            )
            return result
        except asyncio.TimeoutError:
            logger.warning(f"Plugin {plugin.name} timed out")
            return PluginResult(
                plugin_name=plugin.name,
                result_type="error",
                success=False,
                errors=[f"Plugin {plugin.name} timed out after {config.get('timeout', 120)}s"],
            )
        except Exception as e:
            logger.error(f"Plugin {plugin.name} failed: {e}")
            return PluginResult(
                plugin_name=plugin.name,
                result_type="error",
                success=False,
                errors=[f"Plugin {plugin.name} failed: {str(e)}"],
            )

    def launch_scan(self, scan_id: int):
        """Fire-and-forget a scan as a background task."""
        logger.info(f"Launching scan {scan_id} as background task")
        task = asyncio.create_task(self.start_scan(scan_id))
        self._running_tasks[scan_id] = task

        def _on_done(t):
            self._running_tasks.pop(scan_id, None)
            if t.exception():
                logger.error(f"Scan {scan_id} task exception: {t.exception()}")

        task.add_done_callback(_on_done)
        return task

    def cancel_scan(self, scan_id: int) -> bool:
        """Cancel a running scan."""
        task = self._running_tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
            return True
        return False


# Global engine singleton
scan_engine = ScanEngine()
