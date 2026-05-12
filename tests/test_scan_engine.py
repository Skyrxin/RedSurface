import pytest
from app.scan_engine import ScanEngine
from app.database import Scan, ScanResult, ScanStatus
from plugins.base import PluginBase, PluginResult, PluginCategory

class MockPlugin(PluginBase):
    name = "Mock Plugin"
    category = PluginCategory.DISCOVERY
    result_types = ["subdomain"]
    
    async def run(self, target, config=None):
        return PluginResult(
            plugin_name=self.name,
            result_type="subdomain",
            values=["sub1.test.com", "sub2.test.com"]
        )

@pytest.mark.asyncio
async def test_engine_orchestration(db_session, monkeypatch):
    # Setup scan
    scan = Scan(name="Engine Test", target="test.com", target_type="domain")
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)

    engine = ScanEngine(max_concurrent_plugins=2)
    
    # Mock _get_session to return our test db_session
    async def mock_get_session(self):
        return db_session
    monkeypatch.setattr(ScanEngine, "_get_session", mock_get_session)

    # Mock registry to only return our mock plugin
    from plugins import registry
    monkeypatch.setattr(registry, "enabled", lambda: [MockPlugin()])
    monkeypatch.setattr(registry, "all", lambda: [MockPlugin()])

    # Run scan
    await engine.start_scan(scan.id)
    
    # Verify results
    from sqlalchemy import select
    res = await db_session.execute(select(Scan).filter(Scan.id == scan.id))
    scan = res.scalars().first()
    assert scan.status == ScanStatus.COMPLETED.value
    
    res = await db_session.execute(select(ScanResult).filter(ScanResult.scan_id == scan.id))
    results = res.scalars().all()
    assert len(results) == 2
    assert results[0].value == "sub1.test.com"
