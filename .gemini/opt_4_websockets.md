# Optimization Plan 4: Real-time Communication (WebSockets)

## Objective
Upgrade the frontend user experience by streaming scan status updates and new results in real-time, eliminating the need for constant HTTP polling.

## Key Files & Context
- `app/api/scans.py`
- `app/scan_engine.py`
- `app/static/js/app.js` or `app/static/js/graph.js`
- `app/templates/scan_results.html`

## Implementation Steps
1. **WebSocket Manager:** 
   - Create a simple `ConnectionManager` class in `app/api/ws.py` (or within `scans.py`) to handle active WebSocket connections, mapped by `scan_id`.
2. **WebSocket Endpoint:**
   - Add a `@router.websocket("/ws/scans/{scan_id}")` endpoint to accept connections and hold them open.
3. **Event Broadcasting:**
   - Update `ScanEngine` to emit events (e.g., `{"event": "stage_complete", "data": ...}`) to the `ConnectionManager` whenever a plugin finishes or a stage completes.
4. **Frontend Integration:**
   - In the frontend JS, instantiate `new WebSocket(url)`.
   - Add an `onmessage` listener to append new results to the data table and push new nodes to the D3.js graph dynamically without requiring a full page refresh.

## Verification & Testing
- Open a scan results page.
- Start a multi-stage scan.
- Verify that as Stage 1 completes, the UI updates automatically without a manual refresh or background AJAX polling requests.
