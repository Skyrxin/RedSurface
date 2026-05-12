# Optimization Plan 5: Graph Payload Limits

## Objective
Prevent browser freezing and out-of-memory errors on massive OSINT scans by optimizing the payload sent to the D3.js frontend visualization.

## Key Files & Context
- `app/api/scans.py` (specifically `/scans/{scan_id}/graph`)
- `app/static/js/graph.js`

## Implementation Steps
1. **Backend Payload Reduction:**
   - In the `/scans/{scan_id}/graph` endpoint, implement a node threshold (e.g., max 1000 nodes).
   - If `len(results) > threshold`, group nodes of the same `result_type` that share the same parent into a single aggregate node (e.g., an "Emails" node representing 500 email results).
2. **Priority Filtering:**
   - Ensure "tier 1" data (subdomains, explicit identities) are prioritized and not aggressively collapsed.
3. **Frontend Expansion (Optional / Future Phase):**
   - Add logic in `graph.js` so clicking an aggregated node fires an API request to fetch its children.

## Verification & Testing
- Populate a scan with 10,000 dummy results (e.g., 10,000 emails).
- Load the `/scans/{scan_id}/graph` endpoint.
- Verify the JSON payload is significantly smaller and the D3.js visualization loads smoothly, rendering an aggregate node instead of 10,000 individual nodes.
