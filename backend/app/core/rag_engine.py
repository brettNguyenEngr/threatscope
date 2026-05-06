import os
import requests
from app.db.vector_store import get_collection # Adjust import path based on your structure

VULNERS_API_KEY = os.getenv("VULNERS_API_KEY")
VULNERS_BASE_URL = "https://vulners.com/api/v3/search/id"

def fetch_cve_details(cve_id: str) -> str:
    """
    Checks ChromaDB for the CVE description.
    If not found, fetches from Vulners API, saves to ChromaDB, and returns it.
    """
    collection = get_collection()
    
    # 1. Search Local Memory (ChromaDB)
    results = collection.get(ids=[cve_id])
    
    if results and results.get('documents') and len(results['documents']) > 0:
        print(f"[RAG Engine] 🟢 Cache hit for {cve_id}")
        return results['documents'][0]
        
    # 2. Cache Miss: Fetch from external Vulners API
    print(f"[RAG Engine] 🔴 Cache miss for {cve_id}. Fetching from Vulners API...")
    if not VULNERS_API_KEY:
        return f"Warning: {cve_id} not in DB and VULNERS_API_KEY is missing."

    headers = {
        "X-Api-Key": VULNERS_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {"id": [cve_id]}
    
    try:
        response = requests.post(VULNERS_BASE_URL, headers=headers, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()

        if data.get("result") == "error":
            error_msg = data.get("data", {}).get("error", "Unknown API Error")
            print(f"[RAG Engine] 🚨 Vulners API Error: {error_msg}")
            return f"Vulners API Error: {error_msg}"
        
        # Parse the description from the Vulners response
        documents = data.get("data", {}).get("documents", {})
        if not documents:
            print(f"[RAG Engine] ⚠️ No documents returned. Raw Vulners Response: {data}")
            return f"No detailed description found for {cve_id} via Vulners API."

        # Get the first (and only) document
        cve_data = list(documents.values())[0]
        description = cve_data.get("description", "No description available.")
        cvss_score = cve_data.get("cvss", {}).get("score")
        if not cvss_score or cvss_score == 0.0:
            cvss_score = cve_data.get("vulnerScore", "N/A")
        
        # 3. Save to ChromaDB for future scans
        collection.add(
            documents=[description],
            metadatas=[{"source": "vulners", "cvss": str(cvss_score)}],
            ids=[cve_id]
        )
        print(f"[RAG Engine] 💾 Saved {cve_id} to ChromaDB memory.")
        
        return description

    except Exception as e:
        print(f"[RAG Engine] ⚠️ Error fetching {cve_id}: {e}")
        return f"Could not retrieve details for {cve_id}."