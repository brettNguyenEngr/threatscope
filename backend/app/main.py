from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
import asyncio

# Database Imports
from app.db.database import engine, Base, get_db
from app.db.models import ScanResult

# Core Logic Imports
from app.core.rag_engine import fetch_cve_details
from app.core.agent_logic import run_agentic_loop

# This line now sees ScanResult and will actually build the 'scans' table!
Base.metadata.create_all(bind=engine)

# --- App Initialization ---
app = FastAPI(title="ThreatScope Backend", version="0.3")

# Allow Streamlit to communicate with FastAPI (Required for the UI)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Pydantic Models ---
class ScanRequest(BaseModel):
    target_ip: str

# --- API Endpoints ---
@app.get("/")
async def health_check():
    return {"status": "ok", "message": "ThreatScope Backend v0.4 is running."}

@app.post("/scan")
async def run_scan(request: ScanRequest, db: Session = Depends(get_db)):
    """
    v0.4 Endpoint: Autonomous Agentic ReAct Loop + Database Logging.
    """
    target = request.target_ip
    if not target:
        raise HTTPException(status_code=400, detail="Target IP or subnet is required.")

    print(f"--- Received agentic scan request for target: {target} ---")

    try:
        # Trigger autonomous Agentic loop instead of linear v0.3 scan
        final_report = run_agentic_loop(target)

        # Because agent decides what to scan dynamically, we don't have a single
        # linear 'manifest' like in v0.3. Log context of agent run instead.
        manifest = {
            "target": target,
            "scan_type": "Agentic ReAct Loop"
        }

        # --- Save to the Postgres Database ---
        db_scan = ScanResult(
            target_ip=request.target_ip,
            manifest=manifest,
            verdict=final_report
        )
        db.add(db_scan)
        db.commit()
        
        return {
            "status": "Success",
            "target": target,
            "report": final_report
        }

    except Exception as e:
        print(f"Backend Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/test-rag/{cve_id}")
async def test_rag(cve_id: str):
    description = fetch_cve_details(cve_id)
    return {"cve_id": cve_id, "description": description}