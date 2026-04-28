from fastapi import FastAPI, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
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
    v0.1 Mock Endpoint: Simulates an agentic scan and returns dummy data.
    """
    await asyncio.sleep(3)
    
    dummy_manifest = {
        "target": request.target_ip,
        "scan_type": "Simulated Agentic Multi-Pass",
        "simulated_tools_used": ["nmap -sn", "nmap -sV --script vulners"],
        "raw_findings": [
            {"port": 21, "service": "ftp", "version": "vsftpd 2.3.4", "cves": ["CVE-2011-2523"]},
            {"port": 80, "service": "http", "version": "Apache httpd 2.2.8", "cves": ["CVE-2011-3192", "CVE-2009-3555"]}
        ]
    }
    
    dummy_verdict = (
        f"### 🛡️ Agentic Security Verdict for `{request.target_ip}`\n\n"
        "**Summary:** The target host exposes multiple outdated services with critical known vulnerabilities.\n\n"
        "**Key Findings:**\n"
        "* **Port 21 (FTP):** The host is running `vsftpd 2.3.4`, which contains a well-known malicious backdoor (CVE-2011-2523). "
        "An attacker can trigger this by simply appending a smiley face `:)` to the FTP username, opening a root shell.\n"
        "* **Port 80 (HTTP):** The host is running an ancient version of `Apache 2.2.8`. It is vulnerable to remote code execution "
        "and denial of service attacks.\n\n"
        "---\n"
        "*Note: This is v0.1 dummy data to test UI plumbing. The Nmap tools and LLM are not yet attached.*"
    )
    
    # --- NEW: Save the fake scan to the Postgres Database ---
    db_scan = ScanResult(
        target_ip=request.target_ip,
        manifest=dummy_manifest,
        verdict=dummy_verdict
    )
    db.add(db_scan)
    db.commit()
    
    return {
        "manifest": dummy_manifest,
        "verdict": dummy_verdict
    }