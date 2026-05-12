# Optimization Plan 1: Async Database Migration

## Objective
Migrate RedSurface's database layer from synchronous SQLAlchemy to asynchronous SQLAlchemy (`sqlalchemy.ext.asyncio`) with the `aiosqlite` driver. This prevents database I/O from blocking the main `asyncio` event loop.

## Key Files & Context
- `requirements.txt`
- `app/database.py`
- `app/scan_engine.py`
- `app/api/scans.py`
- `app/api/settings.py` (and any other API route files)

## Implementation Steps
1. **Dependencies:** Add `aiosqlite` and update `SQLAlchemy` (if needed) in `requirements.txt`.
2. **Database Config:** 
   - Update `app/database.py`. Change `create_engine` to `create_async_engine`.
   - Update `SessionLocal` to use `async_sessionmaker`.
   - Change `get_db` to an async generator (`async def get_db(): ... yield db ...`).
3. **API Routes Refactoring:**
   - Go through `app/api/scans.py`, `modules.py`, and `settings.py`.
   - Change route handlers to `async def`.
   - Replace standard queries (`db.query(...)`) with async execution: `result = await db.execute(select(Model))`, then `result.scalars().all()`.
   - Update all `.commit()` to `await db.commit()`.
4. **ScanEngine Refactoring:**
   - Update `ScanEngine._get_session()` to return an async session.
   - Refactor database reads and writes in `start_scan` to use `await`.

## Verification & Testing
- Run `python main.py` and ensure the application boots without errors.
- Trigger a new scan and verify that database reads/writes complete successfully and the scan status updates.
- Verify API endpoints return data correctly.
