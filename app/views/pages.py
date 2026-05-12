"""
Page Routes — Serves Jinja2-rendered HTML pages.
"""
from pathlib import Path
from fastapi import APIRouter, Request, Depends
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import Scan, ScanResult, ModuleConfig, get_db

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter()


async def _hydrate_plugin_keys(db: AsyncSession):
    """Load API keys from DB into in-memory plugin objects so is_ready() is accurate."""
    from plugins import registry
    result = await db.execute(select(ModuleConfig))
    configs = result.scalars().all()
    key_map = {c.module_name: c for c in configs}
    for plugin in registry.all():
        mc = key_map.get(plugin.name)
        if mc and mc.api_key:
            keys = {kn: mc.api_key for kn in plugin.api_key_names}
            plugin.configure(api_keys=keys)


@router.get("/")
async def dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    """Main dashboard — shows scan history and quick actions."""
    from plugins import registry

    stmt = select(Scan).order_by(Scan.created_at.desc()).limit(10)
    result = await db.execute(stmt)
    recent_scans = result.scalars().all()

    total_results_stmt = select(func.count()).select_from(ScanResult)
    total_results_res = await db.execute(total_results_stmt)
    total_results = total_results_res.scalar()

    total_scans_stmt = select(func.count()).select_from(Scan)
    total_scans_res = await db.execute(total_scans_stmt)
    total_scans = total_scans_res.scalar()

    running_stmt = select(func.count()).select_from(Scan).filter(Scan.status == "running")
    running_res = await db.execute(running_stmt)
    running_count = running_res.scalar()

    completed_stmt = select(func.count()).select_from(Scan).filter(Scan.status == "completed")
    completed_res = await db.execute(completed_stmt)
    completed_count = completed_res.scalar()

    stats = {
        "total_scans": total_scans,
        "running": running_count,
        "completed": completed_count,
        "total_results": total_results,
    }
    return templates.TemplateResponse(request, "dashboard.html", context={
        "recent_scans": [s.to_dict() for s in recent_scans],
        "stats": stats,
        "modules_count": len(registry.info_all()),
    })


@router.get("/scan/new")
async def new_scan(request: Request, db: AsyncSession = Depends(get_db)):
    """New scan configuration page."""
    from plugins import registry
    await _hydrate_plugin_keys(db)
    # Only domain modules for standard scan
    modules = [m for m in registry.info_all() if "domain" in m.get("target_types", []) or "ip" in m.get("target_types", [])]
    return templates.TemplateResponse(request, "scan_new.html", context={
        "modules": modules,
    })


@router.get("/scan/people")
async def new_people_scan(request: Request, db: AsyncSession = Depends(get_db)):
    """People Lookup OSINT configuration page."""
    from plugins import registry
    await _hydrate_plugin_keys(db)
    # Only people-focused modules
    people_types = ["email", "username", "person"]
    modules = [m for m in registry.info_all() if any(t in people_types for t in m.get("target_types", []))]
    return templates.TemplateResponse(request, "scan_people.html", context={
        "modules": modules,
    })


@router.get("/scan/{scan_id}")
async def scan_results(request: Request, scan_id: int, db: AsyncSession = Depends(get_db)):
    """Scan results page with findings, stats, and export."""
    result = await db.execute(select(Scan).filter(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        return templates.TemplateResponse(request, "404.html", status_code=404)

    results_res = await db.execute(select(ScanResult).filter(ScanResult.scan_id == scan_id))
    results = results_res.scalars().all()

    # Group results by type
    grouped = {}
    for r in results:
        grouped.setdefault(r.result_type, []).append(r.to_dict())

    # Module-level stats (results per module, excluding errors)
    module_stats = {}
    error_count = 0
    for r in results:
        if r.result_type == "error":
            error_count += 1
        else:
            module_stats[r.module_name] = module_stats.get(r.module_name, 0) + 1

    # Sort by count descending
    module_stats = dict(sorted(module_stats.items(), key=lambda x: x[1], reverse=True))
    max_module_count = max(module_stats.values()) if module_stats else 1

    return templates.TemplateResponse(request, "scan_results.html", context={
        "scan": scan.to_dict(),
        "results": grouped,
        "total_results": len(results),
        "module_stats": module_stats,
        "max_module_count": max_module_count,
        "error_count": error_count,
    })


@router.get("/scan/{scan_id}/report")
async def scan_report(request: Request, scan_id: int, db: AsyncSession = Depends(get_db)):
    """Printable PDF report page — standalone, print-optimized layout."""
    result = await db.execute(select(Scan).filter(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        return templates.TemplateResponse(request, "404.html", status_code=404)

    results_res = await db.execute(select(ScanResult).filter(ScanResult.scan_id == scan_id))
    results = results_res.scalars().all()

    # Group results by type
    grouped = {}
    for r in results:
        grouped.setdefault(r.result_type, []).append(r.to_dict())

    # Module-level stats
    module_stats = {}
    for r in results:
        if r.result_type != "error":
            module_stats[r.module_name] = module_stats.get(r.module_name, 0) + 1
    module_stats = dict(sorted(module_stats.items(), key=lambda x: x[1], reverse=True))
    max_module_count = max(module_stats.values()) if module_stats else 1

    return templates.TemplateResponse(request, "report.html", context={
        "scan": scan.to_dict(),
        "results": grouped,
        "total_results": len(results),
        "module_stats": module_stats,
        "max_module_count": max_module_count,
    })


@router.get("/modules")
async def modules_page(request: Request, db: AsyncSession = Depends(get_db)):
    """Browse and configure modules page."""
    from plugins import registry
    await _hydrate_plugin_keys(db)
    modules = registry.info_all()
    return templates.TemplateResponse(request, "modules.html", context={
        "modules": modules,
    })


@router.get("/settings")
async def settings_page(request: Request, db: AsyncSession = Depends(get_db)):
    """API key and settings management page."""
    from app.database import ModuleConfig
    from plugins import registry

    result = await db.execute(select(ModuleConfig))
    configs = result.scalars().all()
    config_map = {c.module_name: c.to_dict() for c in configs}
    modules = registry.info_all()

    return templates.TemplateResponse(request, "settings.html", context={
        "modules": modules,
        "config_map": config_map,
    })
