/**
 * RedSurface — Client-side utilities
 */

// Cancel a running scan
async function cancelScan(scanId) {
    if (!confirm('Cancel this running scan?')) return;
    try {
        await fetch('/api/scans/' + scanId + '/cancel', { method: 'POST' });
        location.reload();
    } catch (err) {
        alert('Failed to cancel scan: ' + err.message);
    }
}

// Delete a scan
async function deleteScan(scanId) {
    if (!confirm('Delete this scan and all its results?')) return;
    try {
        await fetch('/api/scans/' + scanId, { method: 'DELETE' });
        window.location.href = '/';
    } catch (err) {
        alert('Failed to delete scan: ' + err.message);
    }
}

// Initialize scan WebSocket for real-time updates
function initScanWebSocket(scanId) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = protocol + '//' + window.location.host + '/api/ws/scans/' + scanId;
    const socket = new WebSocket(wsUrl);

    socket.onmessage = function(event) {
        const data = JSON.parse(event.data);
        console.log('[WS] New event:', data.event);

        if (data.event === 'results_found' || data.event === 'scan_completed' || data.event === 'scan_failed') {
            // For now, we reload to refresh the full UI state
            // In a future phase, we can append results to the DOM directly
            location.reload();
        }
    };

    socket.onclose = function() {
        console.log('[WS] Connection closed. Falling back to polling.');
        pollScanStatus(scanId);
    };

    return socket;
}

// Poll scan status (Fallback used if WS fails)
function pollScanStatus(scanId, intervalMs = 5000) {
    const poll = async () => {
        try {
            const res = await fetch('/api/scans/' + scanId);
            const data = await res.json();
            if (data.status === 'completed' || data.status === 'failed') {
                location.reload();
            }
        } catch (e) { /* ignore */ }
    };
    setInterval(poll, intervalMs);
}
