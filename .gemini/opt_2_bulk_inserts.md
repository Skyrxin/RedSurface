# Optimization Plan 2: Bulk Database Inserts

## Objective
Optimize database write performance in `ScanEngine` by utilizing SQLAlchemy's bulk insert capabilities instead of appending objects one-by-one in a loop.

## Key Files & Context
- `app/scan_engine.py`
- `app/database.py` (ScanResult model)

## Implementation Steps
1. **Analyze Current Loop:** In `ScanEngine.start_scan`, locate the iteration over `result.values` where `db.add(ScanResult(...))` is called.
2. **Prepare Bulk Data:** 
   - Instead of instantiating `ScanResult` ORM objects, create a list of dictionaries mapping directly to the `ScanResult` table columns (`scan_id`, `module_name`, `result_type`, `value`, `parent_value`, `metadata_json`).
3. **Execute Bulk Insert:**
   - Import `insert` from `sqlalchemy`.
   - Replace the `db.add()` loop and `db.commit()` with:
     ```python
     if bulk_data:
         await db.execute(insert(ScanResult).values(bulk_data))
         await db.commit()
     ```
   *(Note: This uses async syntax, assuming Plan 1 is implemented. If done synchronously, it uses `db.execute(insert(...).values(...))`)*

## Verification & Testing
- Run a large scan (e.g., using a mock plugin that returns 1,000 values).
- Measure the time taken to write results before and after the change.
- Verify the SQLite database contains all 1,000 results with their associated metadata properly saved.
