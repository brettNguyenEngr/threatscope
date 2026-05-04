from fastapi import FastAPI, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.scanner.nmap_runner import execute_basic_scan
import asyncio

# --- Database Imports ---
from app.db.database import engine, Base, get_db
from app.db.models import ScanResult

# This line now sees ScanResult and will actually build the 'scans' table!
Base.metadata.create_all(bind=engine)

# --- App Initialization ---
app = FastAPI(title="ThreatScope Backend", version="0.1")

# --- Pydantic Models ---
class ScanRequest(BaseModel):
    target_ip: str

# --- API Endpoints ---
@app.get("/")
async def health_check():
    return {"status": "ok", "message": "ThreatScope Backend v0.1 is running."}

# Notice we added 'db: Session = Depends(get_db)' here to open a database connection
@app.post("/scan")
async def run_scan(request: ScanRequest, db: Session = Depends(get_db)):
    """
    v0.2 Endpoint: Executes a REAL bvasic nmap scan against the target.
    """

    # Real scan
    real_scan_data = execute_basic_scan(request.target_ip)

    # Package into manifest format
    manifest = {
        "target": request.target_ip,
        "scan_type": "Basic Nmap Version Scan",
        "raw_findings": real_scan_data
    }
    
    dummy_verdict = (
        f"### 🛡️ Agentic Security Verdict for `{request.target_ip}`\n\n"
        "*Note: This is v0.1 dummy data to test UI plumbing. The Nmap tools and LLM are not yet attached.*"
    )
    
    # --- Save to the Postgres Database ---
    db_scan = ScanResult(
        target_ip=request.target_ip,
        manifest=manifest,
        verdict=dummy_verdict
    )
    db.add(db_scan)
    db.commit()
    
    return {
        "manifest": manifest,
        "verdict": dummy_verdict
    }