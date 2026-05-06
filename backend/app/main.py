import json
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

# Database Imports
from app.db.database import engine, Base, get_db
from app.db.models import ScanResult

# Core Logic Imports
from app.core.rag_engine import fetch_cve_details
from app.core.agent_logic import run_agentic_loop

# This line now sees ScanResult and will actually build the 'scans' table!
Base.metadata.create_all(bind=engine)

# --- App Initialization ---
app = FastAPI(title="ThreatScope Backend", version="0.4")

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
    return {"status": "ok", "message": "ThreatScope Backend v0.4 is running (Streaming Mode)."}

@app.post("/scan")
async def run_scan(request: ScanRequest, db: Session = Depends(get_db)):
    """
    v0.4 Endpoint: Streams the ReAct loop directly to the UI via NDJSON.
    """
    target = request.target_ip
    if not target:
        raise HTTPException(status_code=400, detail="Target IP or subnet is required.")

    print(f"--- Received agentic scan stream request for target: {target} ---")

    def event_stream():
        final_report = ""
        try:
            # Iterate over the yielded events from the agent generator
            for event in run_agentic_loop(target):
                # Catch the final answer so we can save it to the DB later
                if event.get("type") == "final_answer":
                    final_report = event.get("content", "")
                
                # Yield the dictionary as a Newline-Delimited JSON (NDJSON) string
                yield json.dumps(event) + "\n"
            
            # After the loop finishes successfully, save to Postgres!
            if final_report:
                manifest = {
                    "target": target,
                    "scan_type": "Agentic ReAct Loop"
                }
                db_scan = ScanResult(
                    target_ip=target,
                    manifest=manifest,
                    verdict=final_report
                )
                db.add(db_scan)
                db.commit()
                print(f"✅ Successfully saved scan for {target} to database.")
                
        except Exception as e:
            print(f"Backend Streaming Error: {e}")
            yield json.dumps({"type": "error", "content": str(e)}) + "\n"

    # Return the generator wrapped in a StreamingResponse
    return StreamingResponse(event_stream(), media_type="application/x-ndjson")

@app.get("/test-rag/{cve_id}")
async def test_rag(cve_id: str):
    description = fetch_cve_details(cve_id)
    return {"cve_id": cve_id, "description": description}