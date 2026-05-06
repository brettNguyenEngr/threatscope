from fastapi import FastAPI, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
import asyncio
from core.rag_engine import fetch_cve_details

# --- Database Imports ---
from app.db.database import engine, Base, get_db
from app.db.models import ScanResult

# Scanner & LLM Imports
from app.scanner.nmap_runner import execute_basic_scan
from app.llm.analyzer import generate_verdict

# This line now sees ScanResult and will actually build the 'scans' table!
Base.metadata.create_all(bind=engine)

# --- App Initialization ---
app = FastAPI(title="ThreatScope Backend", version="0.3")

# --- Pydantic Models ---
class ScanRequest(BaseModel):
    target_ip: str

# --- API Endpoints ---
@app.get("/")
async def health_check():
    return {"status": "ok", "message": "ThreatScope Backend v0.3 is running."}

# Notice we added 'db: Session = Depends(get_db)' here to open a database connection
@app.post("/scan")
async def run_scan(request: ScanRequest, db: Session = Depends(get_db)):
    """
    v0.3 Endpoint: Real nmap scan + llm verdict.
    """

    # Real scan
    real_scan_data = execute_basic_scan(request.target_ip)

    # Package into manifest format
    manifest = {
        "target": request.target_ip,
        "scan_type": "Nmap Version Scan & Vulners Scan",
        "raw_findings": real_scan_data
    }
    
    real_verdict = generate_verdict(manifest)
    
    # --- Save to the Postgres Database ---
    db_scan = ScanResult(
        target_ip=request.target_ip,
        manifest=manifest,
        verdict=real_verdict
    )
    db.add(db_scan)
    db.commit()
    
    return {
        "manifest": manifest,
        "verdict": real_verdict
    }

@app.get("/test-rag/{cve_id}")
async def test_rag(cve_id: str):
    description = fetch_cve_details(cve_id)
    return {"cve_id": cve_id, "description": description}