import pytest
from app.database import Scan, ScanStatus

@pytest.mark.asyncio
async def test_create_scan(client):
    response = await client.post("/api/scans", json={
        "name": "Test Scan",
        "target": "example.com",
        "target_type": "domain",
        "mode": "passive",
        "modules": []
    })
    assert response.status_code == 201
    data = response.json()
    assert data["target"] == "example.com"
    assert data["status"] == "pending"

@pytest.mark.asyncio
async def test_list_scans(client, db_session):
    # Seed a scan
    scan = Scan(name="Old Scan", target="old.com", status=ScanStatus.COMPLETED.value)
    db_session.add(scan)
    await db_session.commit()

    response = await client.get("/api/scans")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1
    assert data[0]["target"] == "old.com"

@pytest.mark.asyncio
async def test_get_scan_not_found(client):
    response = await client.get("/api/scans/9999")
    assert response.status_code == 404
