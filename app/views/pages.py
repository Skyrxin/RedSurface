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


@router.get("/")
async def dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    """Main dashboard — shows scan history and quick actions."""
    from plugins import registry

    stmt = select(Scan).order_by(Scan.created_at.desc()).limit(15)
    result = await db.execute(stmt)
    scans = result.scalars().all()

    # Pre-calculate result counts for each scan to avoid lazy-loading
    scan_dicts = []
    for s in scans:
        count_stmt = select(func.count()).select_from(ScanResult).filter(ScanResult.scan_id == s.id)
        count_res = await db.execute(count_stmt)
        scan_dicts.append(s.to_dict(result_count=count_res.scalar()))

    stats = {
        "total_scans": (await db.execute(select(func.count()).select_from(Scan))).scalar(),
        "running": (await db.execute(select(func.count()).select_from(Scan).filter(Scan.status == "running"))).scalar(),
        "completed": (await db.execute(select(func.count()).select_from(Scan).filter(Scan.status == "completed"))).scalar(),
        "total_results": (await db.execute(select(func.count()).select_from(ScanResult))).scalar(),
    }
    
    return templates.TemplateResponse(request, "dashboard.html", context={
        "recent_scans": scan_dicts,
        "stats": stats,
        "modules_count": len(registry.info_all()),
    })


@router.get("/scan/new")
async def new_scan(request: Request, db: AsyncSession = Depends(get_db)):
    """New scan configuration page."""
    from plugins import registry
    await _hydrate_plugin_keys(db)
    modules = [m for m in registry.info_all() if "domain" in m.get("target_types", []) or "ip" in m.get("target_types", [])]
    return templates.TemplateResponse(request, "scan_new.html", context={
        "modules": modules,
    })


@router.get("/scan/people")
async def new_people_scan(request: Request, db: AsyncSession = Depends(get_db)):
    """People Lookup OSINT configuration page."""
    from plugins import registry
    await _hydrate_plugin_keys(db)
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
    raw_results = results_res.scalars().all()
    
    print(f"DEBUG: Scan {scan_id} results count in DB: {len(raw_results)}")

    # Group results by type and convert to dict
    grouped = {}
    for r in raw_results:
        rtype = r.result_type or "unknown"
        if rtype not in grouped:
            grouped[rtype] = []
        grouped[rtype].append(r.to_dict())

    # Module-level stats
    module_stats = {}
    error_count = 0
    for r in raw_results:
        if r.result_type == "error":
            error_count += 1
        else:
            module_stats[r.module_name] = module_stats.get(r.module_name, 0) + 1

    # Sort stats
    module_stats = dict(sorted(module_stats.items(), key=lambda x: x[1], reverse=True))

    return templates.TemplateResponse(request, "scan_results.html", context={
        "scan": scan.to_dict(result_count=len(raw_results)),
        "results": grouped,
        "total_results": len(raw_results),
        "module_stats": module_stats,
        "error_count": error_count,
    })


@router.get("/scan/{scan_id}/report")
async def scan_report(request: Request, scan_id: int, db: AsyncSession = Depends(get_db)):
    """Printable PDF report page."""
    result = await db.execute(select(Scan).filter(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        return templates.TemplateResponse(request, "404.html", status_code=404)

    results_res = await db.execute(select(ScanResult).filter(ScanResult.scan_id == scan_id))
    raw_results = results_res.scalars().all()

    grouped = {}
    for r in raw_results:
        rtype = r.result_type or "unknown"
        if rtype not in grouped:
            grouped[rtype] = []
        grouped[rtype].append(r.to_dict())

    return templates.TemplateResponse(request, "report.html", context={
        "scan": scan.to_dict(result_count=len(raw_results)),
        "results": grouped,
        "total_results": len(raw_results),
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
    
    # Enrich configs with multi-key info for the UI
    config_map = {}
    for c in configs:
        d = c.to_dict()
        keys = {}
        if c.api_key: keys["api_key"] = True
        extra = c.extra_config or {}
        for k in extra:
            if k.endswith(("_key", "_id", "_secret", "_token")) or k in ("intelx", "serpapi", "google_search_cx"):
                keys[k] = True
        d["keys"] = keys
        config_map[c.module_name] = d

    modules = registry.info_all()
    return templates.TemplateResponse(request, "settings.html", context={
        "modules": modules,
        "config_map": config_map,
    })
