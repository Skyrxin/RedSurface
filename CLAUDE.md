# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

RedSurface is a modular external reconnaissance / attack surface intelligence web app. It runs a plugin-based async scan engine against a domain (or other target type), persists findings to SQLite, streams progress over WebSockets, and renders results as an interactive D3.js node-link graph.

## Commands

```powershell
# Setup
python -m venv venv
.\venv\Scripts\Activate
pip install -r requirements.txt

# Run the web app (http://127.0.0.1:5000, docs at /docs)
python main.py

# Run tests (pytest-asyncio, in-memory SQLite; see tests/conftest.py)
pytest
pytest tests/test_scan_engine.py::test_name   # single test
pytest -k "keyword"

# Run a full scan from the CLI without the web UI
python gemini_modules/native_scan_runner.py <target> [target_type]
```

There is no lint/format command configured in this repo; check with the user before assuming one.

## Architecture

**App factory & lifespan** (`app/__init__.py`): `create_app()` builds the FastAPI app; the `lifespan` context calls `init_db()` and `registry.discover_plugins()` on startup. Routers are mounted under `/api` (`scans`, `modules`, `settings`) plus a non-prefixed page router (`app/views/pages.py`) for Jinja2-rendered views.

**Plugin system** (`plugins/`): `plugins/base.py` defines `PluginBase` (abstract `async run(target, config) -> PluginResult`) and `PluginResult` (parallel arrays: `values`, `parent_values`, `per_value_metadata`, plus a global `metadata` dict). `plugins/__init__.py` holds the global `registry` singleton; `discover_plugins()` walks `plugins/{discovery,osint,threat_intel,internal}/`, imports every module, and auto-registers any `PluginBase` subclass found — there is no manual registration list, so a new plugin file with a `PluginBase` subclass is picked up automatically. Plugin categories map to `PluginCategory` (`Discovery`, `OSINT`, `Threat Intelligence`, `Internal`, `Tool Integration`).

To add a plugin: create `plugins/<category>/<name>.py`, subclass `PluginBase`, set metadata (`name`, `category`, `api_type`, `requires_api_key`, `api_key_names`, `result_types`, `target_types`), implement `async run()`.

**Scan orchestration** (`app/scan_engine.py`): `ScanEngine.start_scan()` loads the `Scan` row, resolves which plugins to run (explicit `modules` list in `scan.config`, or all enabled plugins matching the target type), hydrates each plugin's API keys from the `module_configs` table, then runs plugins in three sequential stages — Discovery, then Internal, then everything else — so later stages can act on subdomains/IPs discovery produces. Within a stage, plugins run concurrently via `asyncio.gather`, bounded by `asyncio.Semaphore(max_concurrent_plugins=10)` and a per-plugin timeout (`asyncio.wait_for`, default 120s). Results are bulk-inserted (`insert(ScanResult).values(list_of_dicts)`) per stage, and a `results_found` event is broadcast over WebSocket only *after* the DB commit succeeds.

**Persistence** (`app/database.py`): async SQLAlchemy (`sqlalchemy.ext.asyncio`) over SQLite (`aiosqlite`), DB file at `data/redsurface.db`. Core tables: `Scan` (job + `config` JSON blob of enabled modules), `ScanResult` (one row per finding: `module_name`, `result_type`, `value`, `parent_value`, `metadata_json`), `ModuleConfig` (API keys / per-plugin settings, keyed by `module_name`). `get_db()` is the FastAPI dependency; tests override it via `app.dependency_overrides` with an in-memory SQLite session (see `tests/conftest.py`).

**Real-time updates** (`app/api/ws.py`): a global `ConnectionManager` (`manager`) maps `scan_id -> [WebSocket]`; `broadcast_to_scan` sends to all watchers with a 2s timeout per send and silently drops dead connections.

**Graph rendering**: `app/api/scans.py`'s `/scans/{scan_id}/graph` endpoint transforms `ScanResult` rows into a D3.js node-link payload consumed by the frontend graph view.

## Important async patterns (from prior debugging — see GEMINI.md for full incident log)

- Never use blocking/synchronous I/O inside a plugin's `run()` — use `httpx`/`asyncio`-compatible libraries, or the event loop stalls for every concurrent scan.
- Use `sqlalchemy.ext.asyncio` patterns throughout (`await db.execute(select(...))`, `result.scalars()`); do not mix in sync `.query()`-style calls.
- Insert scan results in bulk (`insert(Model).values(list_of_dicts)`), never one `db.add()` per row — this was a major perf bottleneck.
- Put per-result context in `PluginResult.per_value_metadata` (parallel to `values`), not the global `metadata` dict — global metadata gets replicated onto every row in the DB and causes UI duplication.
- Broadcast WebSocket events only after the triggering DB commit completes, so clients never see a state the DB doesn't have yet.

## Repo layout notes

- `_legacy/` is the pre-rewrite CLI version of this tool (Docker/CLI based); not part of the current FastAPI app, don't use it as a reference for current patterns.
- `gemini_modules/`, `project_dev/`, `.gemini/` contain maintenance/debug scripts and planning notes from prior AI-assisted work, not production code paths.
- `GEMINI.md` is a parallel instructions file maintained for Gemini; it contains an "Anti-Patterns & Lessons Learned" log worth reading if you touch `ScanEngine` or plugin async code.
