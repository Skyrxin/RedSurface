# RedSurface Master Optimizations Plan

This document serves as the index for the proposed project-wide optimizations for RedSurface. Each optimization has been broken down into a separate, independent planning document.

## 1. Async Database Migration
**File:** `opt_1_async_db.md`
**Goal:** Prevent the SQLite database from blocking the asynchronous FastAPI event loop by migrating to `aiosqlite` and `sqlalchemy.ext.asyncio`.

## 2. Bulk Database Inserts
**File:** `opt_2_bulk_inserts.md`
**Goal:** Dramatically improve database write performance during large OSINT scans by replacing iterative `db.add()` calls with SQLAlchemy bulk inserts.

## 3. Concurrency Limits (Semaphores)
**File:** `opt_3_concurrency.md`
**Goal:** Prevent system resource exhaustion and target API bans by implementing an `asyncio.Semaphore` to limit the number of concurrently running plugins.

## 4. Real-time Communication (WebSockets/SSE)
**File:** `opt_4_websockets.md`
**Goal:** Improve UX by replacing polling with WebSockets or Server-Sent Events, streaming scan results to the frontend in real-time.

## 5. Graph Payload Optimization
**File:** `opt_5_graph_payload.md`
**Goal:** Prevent browser crashes on massive graphs by implementing server-side node grouping, limits, and lazy-loading for D3.js.

## 6. Formal Test Suite
**File:** `opt_6_testing.md`
**Goal:** Ensure reliability and prevent regressions by introducing `pytest-asyncio` and `respx` for mock testing async plugins and endpoints.
