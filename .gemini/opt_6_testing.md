# Optimization Plan 6: Formal Test Suite

## Objective
Establish a formal, automated test suite for RedSurface to ensure reliability, prevent regressions during refactoring, and safely mock external network calls.

## Key Files & Context
- `requirements.txt`
- `pytest.ini` (Create new)
- `tests/` directory (Create new)
- `tests/conftest.py`
- `tests/test_scan_engine.py`
- `tests/test_api_scans.py`

## Implementation Steps
1. **Dependencies:** Add `pytest`, `pytest-asyncio`, `respx` (for mocking `httpx`), and `httpx` (for testing the FastAPI app) to `requirements.txt`.
2. **Configuration:** Create `pytest.ini` and configure `asyncio_mode = auto`.
3. **Fixtures:** In `tests/conftest.py`, setup fixtures for:
   - An in-memory SQLite database (`sqlite:///:memory:`).
   - A FastAPI `TestClient` or `AsyncClient`.
   - A mock plugin that always returns a predictable `PluginResult`.
4. **Test Cases:**
   - `test_scan_engine.py`: Test that the engine processes plugins correctly, groups them by stage, and handles timeouts/exceptions gracefully.
   - `test_api_scans.py`: Test API CRUD operations for scans.

## Verification & Testing
- Run `pytest` from the root directory.
- Ensure all tests pass.
- Verify that `respx` successfully intercepts external HTTP calls in test plugins so the test suite runs completely offline.
