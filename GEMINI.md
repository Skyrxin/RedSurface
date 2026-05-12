# RedSurface (redsurface)

RedSurface is a modular, high-performance external reconnaissance and attack surface intelligence platform. It features an async plugin engine (31+ plugins), technology fingerprinter with CVE mapping, and an interactive D3.js attack surface graph.

## Project Structure

- `main.py`: Entry point for the FastAPI web server.
- `app/`: Core web application.
    - `api/`: REST endpoints (scans, modules, settings).
    - `database.py`: SQLAlchemy/SQLite persistence layer.
    - `scan_engine.py`: Orchestrates async plugin execution.
    - `static/`: Glassmorphic CSS and D3.js visualization.
- `plugins/`: Highly modular plugin system.
    - `base.py`: Abstract base class and `PluginResult` definitions.
    - `discovery/`, `osint/`, `threat_intel/`, `internal/`: Plugin categories.
- `modules/`: Core reconnaissance logic (DNS, Fingerprinting, OSINT).
- `gemini_modules/`: Reusable test and maintenance scripts (e.g., native scan runner).
- `utils/`: Logging and caching utilities.

## Core Technologies

- **Backend:** Python 3.10+, FastAPI, Uvicorn, SQLAlchemy (SQLite).
- **Async:** `httpx`, `asyncio`, `dns.asyncresolver`.
- **Frontend:** Jinja2 templates, Vanilla CSS, D3.js.
- **Recon:** Wappalyzer-style fingerprinting, NVD CVE API integration.

## Development Workflow

### Environment Setup
```powershell
python -m venv venv
.\venv\Scripts\Activate
pip install -r requirements.txt
```

### Running the Application
```powershell
python main.py
```
- Web UI: `http://127.0.0.1:5000`
- API Docs: `http://127.0.0.1:5000/docs`

### Plugin Development
To add a new plugin:
1. Create a new file in `plugins/<category>/<name>.py`.
2. Subclass `PluginBase` from `plugins.base`.
3. Implement the `async run(target, config)` method.
4. Define metadata (`name`, `category`, `result_types`, etc.).

### Testing
- **Native Scan Runner:** Use `python gemini_modules/native_scan_runner.py <target> [target_type]` to run a full native scan without using the Web UI.
- **Manual Verification:** Individual plugins can still be verified by directly invoking their logic via custom scripts.
- **TODO:** Implement a formal test suite.

### Documentation Mandate
- **Automatic Updates:** The `GEMINI.md` file MUST be updated automatically after every task, fix, or update to reflect the latest project state, tools, and protocols.

## Architecture Patterns

- **Plugin Registry:** Plugins are dynamically loaded from the `plugins/` directory.
- **Async Orchestration:** `ScanEngine` manages a pool of `asyncio.Task` objects for concurrent plugin execution.
- **Smart OSINT Enrichment:** Discovered social profiles are automatically enriched via `fetch_profile_metadata`, which parses Open Graph (OG) tags to extract real names and bios, transforming raw links into actionable intelligence.
- **Identity Pivoting:** High-signal metadata (e.g., a real name found on a social profile) is used to bridge identities between pseudonyms and real-world individuals, suggesting further targeted scans.
- **Per-Value Metadata:** Plugins utilize `per_value_metadata` to store unique context for each individual result (e.g., specific bios/titles), ensuring clean UI rendering and preventing data duplication across scan result rows.
- **Result Persistence:** Scan findings are stored in SQLite and can be exported as JSON or CSV.
- **Graph Visualization:** Results are transformed into a node-link graph for D3.js in `app/api/scans.py`.

## Security Considerations

- **Authorized Use Only:** Intended for security research and authorized testing.
- **Active Recon:** Modules in `modules/active_recon.py` (e.g., directory brute-force) interact directly with targets and should be used with caution.
- **API Keys:** Sensitive keys are stored in the database (`module_configs` table) and managed via the Settings page. Avoid logging or hardcoding these keys.
    - **Google Custom Search:** Requires `google_api_key` and `google_search_cx` for reliable social media discovery.
    - **GitHub:** `github_token` is recommended to increase rate limits for OSINT collection.
    - **SerpApi:** `serpapi` can be used as a fallback or alternative for search engine results.

## System Protocols & AI Instructions
*   **Automatic Updates:** The `GEMINI.md` file MUST be updated automatically after every task, fix, or update to reflect the latest project state, tools, and protocols. No user confirmation is required for these updates.
*   **Context Verification:** Before modifying any `async` orchestration in `ScanEngine` or adding new OSINT plugins, verify you understand the current rate-limiting and error-handling mechanisms to avoid breaking the asynchronous flow.
*   **Code Style:** Write clean, modular Python. Always use type hinting. Ensure all new plugins strictly adhere to the `PluginBase` structure and return properly formatted `PluginResult` objects.

## Current Focus & Active Tasks
- [x] **Task:** Fix OSINT profile discovery and implement Hybrid API/Scraping approach.
- [x] **Task:** Implement Smart OSINT Enrichment (OG Tag parsing and Metadata extraction).
- [x] **Task:** Fix UI duplication by transitioning plugins to `per_value_metadata`.
- [x] **Task:** Restore rich metadata rendering in UI for `per_value_metadata` results.
- [x] **Task:** Implement "Full Username OSINT" via the `Username Web Discovery` plugin.
- [x] **Task:** Implement "Smart Full Name OSINT" via the `Web Profile Discovery` plugin.
- [x] **Task:** Create reusable native scan test runner in `gemini_modules/`.
- [x] **Task:** Implement Async Database Migration (Optimization Plan 1).
- [x] **Task:** Implement Bulk Database Inserts (Optimization Plan 2).
- [x] **Task:** Implement Concurrency Limits (Optimization Plan 3).
- [x] **Task:** Implement Real-time Communication (Optimization Plan 4).
- [ ] **Task:** Implement a formal test suite (moved from TODOs).
- [ ] **Task:** Refine error handling for HTTP timeouts in async plugins.

## Anti-Patterns & Lessons Learned (Error Log)
- **Mistake:** Using synchronous blocking calls inside async plugins.
- **Solution:** Always use `httpx` or `asyncio` compatible libraries inside `plugins/` to prevent locking the FastAPI event loop.
- **Mistake:** Mixing synchronous SQLAlchemy patterns (like `.query()`) with an asynchronous engine.
- **Solution:** Use `sqlalchemy.ext.asyncio` patterns: `await db.execute(select(...))` and `result.scalars()` to interact with the database without blocking the event loop.
- **Mistake:** Forgetting to await database transactions (`commit`, `refresh`, `close`) in an async context.
- **Solution:** Ensure all session-level operations are awaited to prevent "greenlet" or "coroutine never awaited" errors.
- **Mistake:** Iteratively calling `db.add()` for thousands of scan results.
- **Solution:** Use SQLAlchemy's bulk insert capabilities (`db.execute(insert(Model).values(list_of_dicts))`) to drastically improve persistence performance.
- **Mistake:** Launching dozens of network-heavy async tasks simultaneously.
- **Solution:** Use an `asyncio.Semaphore(n)` to control concurrency, preventing local resource exhaustion and remote IP bans.
- **Mistake:** Storing lists of enriched data in global `PluginResult.metadata`.
- **Solution:** This causes the `ScanEngine` to replicate the entire list across every result row in the database, leading to massive UI duplication. Use `per_value_metadata` to align specific context with specific values.
- **Mistake:** UI template only looking at global metadata keys (e.g., `'profiles'`) after backend transitioned to `per_value_metadata`.
- **Solution:** Update Jinja templates to check both global and per-row metadata fields to ensure rich designs are preserved during architectural shifts.
- **Mistake:** Relying on fragile HTML scrapers for major search engines (Google/DDG) without robust fallback or API integration.
- **Solution:** Use the Hybrid API approach (e.g., Google CSE) and resilient link extraction patterns as implemented in the Smart OSINT fix.
