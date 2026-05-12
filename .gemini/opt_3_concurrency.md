# Optimization Plan 3: Concurrency Limits (Semaphores)

## Objective
Protect system resources and avoid rate-limiting/bans by limiting the number of plugin tasks that can run concurrently within a single scan stage.

## Key Files & Context
- `app/scan_engine.py`

## Implementation Steps
1. **Initialize Semaphore:** 
   - In `ScanEngine.start_scan` (or as a class-level/instance-level parameter), instantiate an `asyncio.Semaphore(max_concurrent_plugins)`. The default value should be sensible, e.g., 5 or 10.
2. **Apply Semaphore to Runner:**
   - Modify the `_run_plugin` method to require the semaphore.
   - Wrap the plugin execution block in an `async with semaphore:` context manager.
   ```python
   async def _run_plugin(self, plugin: PluginBase, target: str, config: dict, semaphore: asyncio.Semaphore):
       async with semaphore:
           # Existing plugin run logic
   ```
3. **Update Invocation:** 
   - Update the loop in `start_scan` that creates tasks to pass the semaphore to `_run_plugin`.

## Verification & Testing
- Add `await asyncio.sleep(2)` to a few test plugins.
- Start a scan with 10 test plugins enabled and `max_concurrent_plugins` set to 2.
- Verify via the logs that only 2 plugins start simultaneously, and others wait until a slot opens up.
