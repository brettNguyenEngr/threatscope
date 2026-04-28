from sqlalchemy import Column, Integer, String, Text, DateTime, JSON
from datetime import datetime
from app.db.database import Base

class ScanResult(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_ip = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # We use JSON to store the raw Nmap/Vulners output natively
    manifest = Column(JSON)  
    
    # We use Text for the LLM's markdown report since it can be long
    verdict = Column(Text)