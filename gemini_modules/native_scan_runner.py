
import asyncio
import sys
import os
import json
from datetime import datetime
from sqlalchemy import select

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from app import database as db_module
from app.database import init_db, Scan, ScanResult, ScanStatus, AsyncSessionLocal
from app.scan_engine import ScanEngine
from plugins import registry

async def run_native_scan(target, target_type="person", mode="passive"):
    """
    Executes a native RedSurface scan for a given target.
    Matches the exact flow of the production ScanEngine.
    """
    print(f"[*] Starting Native RedSurface Scan for: {target} ({target_type})")
    
    # Initialize Database and Plugins
    await db_module.init_db()
    registry.discover_plugins()
    print(f"[*] Loaded {len(registry.all())} plugins")
    
    if db_module.AsyncSessionLocal is None:
         print("[!] Failed to initialize AsyncSessionLocal")
         return None

    async with db_module.AsyncSessionLocal() as db:
        try:
            # Create Scan Record
            new_scan = Scan(
                name=f"Gemini Native Scan - {target}",
                target=target,
                target_type=target_type,
                mode=mode,
                config={"modules": []} # Runs all relevant plugins
            )
            db.add(new_scan)
            await db.commit()
            await db.refresh(new_scan)
            
            scan_id = new_scan.id
            print(f"[*] Created Scan ID: {scan_id}")
            
            # Start Engine
            engine = ScanEngine()
            print(f"[*] Dispatching ScanEngine...")
            await engine.start_scan(scan_id)
            
            # Refresh and fetch results
            await db.refresh(new_scan)
            result = await db.execute(select(ScanResult).filter(ScanResult.scan_id == scan_id))
            results = result.scalars().all()
            
            print(f"\n--- Scan Results (ID: {scan_id} | Status: {new_scan.status}) ---")
            if not results:
                print("[-] No results found.")
            else:
                for r in results:
                    print(f"- [{r.module_name}] {r.result_type}: {r.value}")
                    if r.metadata_json and 'profiles' in r.metadata_json:
                        for p in r.metadata_json['profiles']:
                            print(f"  > [{p['platform']}] {p['title']} ({p['url']}) - Score: {p.get('match_quality', 'N/A')}")
            
            print(f"\n[*] Total Results: {len(results)}")
            print(f"[*] Duration: {new_scan.duration_seconds}s")
            return scan_id
            
        except Exception as e:
            print(f"[!] Native scan failure: {e}")
            import traceback
            traceback.print_exc()
            return None
        finally:
            await db.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python gemini_modules/native_scan_runner.py <target> [target_type]")
        sys.exit(1)
        
    target = sys.argv[1]
    t_type = sys.argv[2] if len(sys.argv) > 2 else "person"
    
    asyncio.run(run_native_scan(target, target_type=t_type))
