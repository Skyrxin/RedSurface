"""
Page Routes — Serves Jinja2-rendered HTML pages.
"""
from pathlib import Path
from fastapi import APIRouter, Request, Depends
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import Scan, ScanResult, ModuleConfig, get_db

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter()


def _hydrate_plugin_keys(db: Session):
    """Load API keys from DB into in-memory plugin objects so is_ready() is accurate."""
    from plugins import registry
    configs = db.query(ModuleConfig).all()
    key_map = {c.module_name: c for c in configs}
    for plugin in registry.all():
        mc = key_map.get(plugin.name)
        if mc and mc.api_key:
            keys = {kn: mc.api_key for kn in plugin.api_key_names}
            plugin.configure(api_keys=keys)


@router.get("/")
def dashboard(request: Request, db: Session = Depends(get_db)):
    """Main dashboard — shows scan history and quick actions."""
    from plugins import registry

    recent_scans = (
        db.query(Scan).order_by(Scan.created_at.desc()).limit(10).all()
    )
    total_results = db.query(ScanResult).count()
    stats = {
        "total_scans": db.query(Scan).count(),
        "running": db.query(Scan).filter(Scan.status == "running").count(),
        "completed": db.query(Scan).filter(Scan.status == "completed").count(),
        "total_results": total_results,
    }
    return templates.TemplateResponse(request, "dashboard.html", context={
        "recent_scans": [s.to_dict() for s in recent_scans],
        "stats": stats,
        "modules_count": len(registry.info_all()),
    })


@router.get("/scan/new")
def new_scan(request: Request, db: Session = Depends(get_db)):
    """New scan configuration page."""
    from plugins import registry
    _hydrate_plugin_keys(db)
    modules = registry.info_all()
    return templates.TemplateResponse(request, "scan_new.html", context={
        "modules": modules,
    })


@router.get("/scan/{scan_id}")
def scan_results(request: Request, scan_id: int, db: Session = Depends(get_db)):
    """Scan results page with findings, stats, and export."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return templates.TemplateResponse(request, "404.html", status_code=404)

    results = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).all()

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
def scan_report(request: Request, scan_id: int, db: Session = Depends(get_db)):
    """Printable PDF report page — standalone, print-optimized layout."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return templates.TemplateResponse(request, "404.html", status_code=404)

    results = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).all()

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
def modules_page(request: Request, db: Session = Depends(get_db)):
    """Browse and configure modules page."""
    from plugins import registry
    _hydrate_plugin_keys(db)
    modules = registry.info_all()
    return templates.TemplateResponse(request, "modules.html", context={
        "modules": modules,
    })


@router.get("/settings")
def settings_page(request: Request, db: Session = Depends(get_db)):
    """API key and settings management page."""
    from app.database import ModuleConfig
    from plugins import registry

    configs = db.query(ModuleConfig).all()
    config_map = {c.module_name: c.to_dict() for c in configs}
    modules = registry.info_all()

    return templates.TemplateResponse(request, "settings.html", context={
        "modules": modules,
        "config_map": config_map,
    })
