"""
Scans API — REST endpoints for creating, listing, and managing scans.
"""
import csv
import io
import json
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import Scan, ScanResult, ScanStatus, get_db
from app.scan_engine import scan_engine

router = APIRouter(tags=["scans"])


class ScanCreate(BaseModel):
    """Request body for creating a new scan."""
    name: str
    target: str
    target_type: str = "domain"  # domain | email | username | person
    mode: str = "passive"  # passive | active
    modules: list[str] = []  # Empty = all enabled modules


@router.post("/scans", status_code=201)
async def create_scan(scan_in: ScanCreate, db: AsyncSession = Depends(get_db)):
    """Create a new scan and start it immediately."""
    scan = Scan(
        name=scan_in.name,
        target=scan_in.target,
        target_type=scan_in.target_type,
        mode=scan_in.mode,
        config={"modules": scan_in.modules},
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Launch scan in background
    scan_engine.launch_scan(scan.id)

    return scan.to_dict()


@router.get("/scans")
async def list_scans(
    limit: int = 50,
    offset: int = 0,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """List all scans with optional status filter."""
    stmt = select(Scan).order_by(Scan.created_at.desc())
    if status:
        stmt = stmt.filter(Scan.status == status)
    
    result = await db.execute(stmt.offset(offset).limit(limit))
    scans = result.scalars().all()
    return [s.to_dict() for s in scans]


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get scan details by ID."""
    result = await db.execute(select(Scan).filter(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan.to_dict()


@router.get("/scans/{scan_id}/results")
async def get_scan_results(
    scan_id: int,
    result_type: Optional[str] = None,
    module: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Get results for a specific scan, with optional filters."""
    result = await db.execute(select(Scan).filter(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    stmt = select(ScanResult).filter(ScanResult.scan_id == scan_id)
    if result_type:
        stmt = stmt.filter(ScanResult.result_type == result_type)
    if module:
        stmt = stmt.filter(ScanResult.module_name == module)

    res = await db.execute(stmt)
    results = res.scalars().all()
    
    return {
        "scan": scan.to_dict(),
        "results": [r.to_dict() for r in results],
        "total": len(results),
    }


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a scan and its results."""
    result = await db.execute(select(Scan).filter(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Cancel if running
    if scan.status == ScanStatus.RUNNING.value:
        scan_engine.cancel_scan(scan_id)

    await db.delete(scan)
    await db.commit()
    return {"detail": "Scan deleted"}


@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Cancel a running scan."""
    result = await db.execute(select(Scan).filter(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.RUNNING.value:
        raise HTTPException(status_code=400, detail="Scan is not running")

    cancelled = scan_engine.cancel_scan(scan_id)
    if cancelled:
        scan.status = ScanStatus.CANCELLED.value
        await db.commit()
        return {"detail": "Scan cancelled"}
    raise HTTPException(status_code=400, detail="Could not cancel scan")


@router.get("/scans/{scan_id}/export")
async def export_scan(
    scan_id: int,
    format: str = "json",
    db: AsyncSession = Depends(get_db),
):
    """Export scan results as JSON or CSV."""
    result = await db.execute(select(Scan).filter(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    res = await db.execute(select(ScanResult).filter(ScanResult.scan_id == scan_id))
    results = res.scalars().all()
    
    filename_base = f"redsurface_{scan.target}_{scan.id}"

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Type", "Value", "Module", "Time"])
        for r in results:
            writer.writerow([
                r.result_type,
                r.value,
                r.module_name,
                str(r.created_at) if r.created_at else "",
            ])
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename_base}.csv"},
        )
    else:
        # JSON export
        export_data = {
            "scan": scan.to_dict(),
            "results": [r.to_dict() for r in results],
            "total": len(results),
        }
        json_str = json.dumps(export_data, indent=2, default=str)
        return StreamingResponse(
            iter([json_str]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename_base}.json"},
        )


@router.get("/scans/{scan_id}/graph")
async def get_scan_graph(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get graph data for D3.js visualization."""
    result = await db.execute(select(Scan).filter(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    res = await db.execute(select(ScanResult).filter(ScanResult.scan_id == scan_id))
    results = res.scalars().all()
    
    return {
        "target": scan.target,
        "results": [r.to_dict() for r in results],
        "total": len(results),
    }
