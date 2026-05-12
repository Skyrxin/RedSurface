"""
WebSocket Manager — Handles real-time communication for scan updates.
"""
from typing import Dict, List, Any
from fastapi import WebSocket


class ConnectionManager:
    """Manages active WebSocket connections for real-time updates."""

    def __init__(self):
        # Maps scan_id -> list of active websockets
        self.active_connections: Dict[int, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, scan_id: int):
        """Accept a connection and track it by scan_id."""
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)

    def disconnect(self, websocket: WebSocket, scan_id: int):
        """Remove a connection."""
        if scan_id in self.active_connections:
            self.active_connections[scan_id].remove(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def broadcast_to_scan(self, scan_id: int, message: Any):
        """Send a message to all clients watching a specific scan with timeout protection."""
        if scan_id in self.active_connections:
            import asyncio
            # We iterate over a copy to avoid issues if a connection is dropped during broadcast
            for connection in list(self.active_connections[scan_id]):
                try:
                    # Use a short timeout to prevent blocking the entire engine
                    await asyncio.wait_for(connection.send_json(message), timeout=2.0)
                except Exception:
                    # If sending fails or times out, the connection might be closed
                    self.disconnect(connection, scan_id)


# Global manager singleton
manager = ConnectionManager()
