# ThreatScope — Agentic Vulnerability Intelligence for Fast Network Triage

An **autonomous, evidence-driven cybersecurity analysis agent** that runs Nmap-based reconnaissance, enriches findings with CVE intelligence via RAG, and generates a human-ready security report—while streaming its reasoning steps in real time.

---

## **Motivation**

Security analysts routinely face a **translation gap**:

- **Raw scan output** (open ports, service banners, script results) is high-signal but not decision-ready.
- **Vulnerability identifiers** (CVE lists) lack context without fast, reliable enrichment.
- **Time pressure** demands prioritization and clarity, yet traditional tooling often produces fragmented evidence.

ThreatScope closes that gap by combining **tool-driven scanning** with an **agentic reasoning loop** that:

- systematically investigates a target,
- retrieves just-in-time vulnerability context,
- and produces an evidence-based report oriented around **impact, prioritization, and recommended actions**.

Design intent: **“Investigate, don’t fix.”** ThreatScope is built as a *read-only observability* assistant—optimized for analysis and reporting rather than remediation or exploitation (though this may be a future goal).

---

## **Project Demo (Video)**

[![Watch the ThreatScope Demo](https://img.youtube.com/vi/fKEm7xLDY-c /0.jpg)](https://www.youtube.com/watch?v=fKEm7xLDY-c )

> 💡 **Tip:** Click the image above to watch the full 5-minute technical walkthrough on YouTube.

---

## **Key Features**

- **Agentic ReAct-style workflow (Thought → Action → Observation)**  
The backend runs a bounded, tool-using loop that decides what to do next and when to stop.
- **Autonomous scanning + reasoning (with guardrails)**  
The agent is constrained to a small, explicit toolbox (discovery → enumeration → vulnerability mapping → CVE enrichment).
- **Live streaming analysis to the UI**  
The FastAPI backend streams the agent’s progress to the Streamlit frontend using **NDJSON**, so the “thinking” is observable in real time.
- **CVE enrichment with caching (RAG)**  
CVE descriptions are fetched on-demand and **cached in ChromaDB** to make subsequent scans faster and more consistent.
- **Evidence-first reporting**  
The final output is a structured markdown report (Executive Summary → Port Analysis → Recommended Actions), designed to be pasted into tickets or briefs.
- **Persistence for scan history**  
Final reports are stored in **PostgreSQL** for auditability and trend tracking.

---

## **Technical Deep Dive**

### **Architecture at a Glance**

- **Frontend**: `Streamlit` (`frontend/app.py`)  
Provides a simple operator console that starts a scan and renders:
  - live terminal-style logs,
  - and the final markdown report.
- **Backend**: `FastAPI` (`backend/app/main.py`)  
Exposes a streaming `/scan` endpoint that runs the agent loop and persists results.
- **LLM Provider**: **OpenRouter** (via HTTP calls)  
The agent loop calls `https://openrouter.ai/api/v1/chat/completions` using:
  - `OPENROUTER_API_KEY`
  - `OPENROUTER_MODEL`
- **Tooling**: `python-nmap` + Nmap Scripting Engine  
The agent uses `python-nmap` to run:
  - host discovery (`-sn`)
  - fast service enumeration (`-F -sV`)
  - targeted vulnerability mapping (`-p <ports> -sV --script vulners`)
- **RAG / Memory**: `ChromaDB` (persistent)  
CVE details are cached in a local persistent Chroma collection (default path is `CHROMA_PERSIST_DIRECTORY` in the backend container).
- **Database**: `PostgreSQL`  
Stores scan results (target + manifest metadata + final verdict/report).

### **Agentic Flow (What Actually Happens)**

ThreatScope’s agent is implemented as a **bounded generator loop** (`backend/app/core/agent_logic.py`) that yields events for streaming UI updates:

1. **System prompt defines constraints & output contract**
  The agent must respond with **one JSON object per step**, choosing either:
  - a tool invocation (`{"tool": "...", "arguments": {...}}`), or
  - a conclusion (`{"final_answer": "..."}`) with a required report structure.
2. **Toolbox-driven actions (no hidden capabilities)**
  The agent can only call the registered tools:
  - `ping_sweep(target_subnet)` → discovers live hosts (and excludes “friendly” containers)
  - `port_scan(target_ip)` → enumerates open ports + service/version hints
  - `vulners_scan(target_ip, port_list)` → runs `--script vulners` only on known-open ports and extracts CVE IDs
  - `fetch_cve(cve_id)` → retrieves a human-readable description via RAG cache/API
3. **RAG-backed CVE enrichment** (`backend/app/core/rag_engine.py`)
  For each relevant CVE, the backend:
  - checks ChromaDB for a cached description,
  - on cache miss, calls the **Vulners API** (`/api/v3/search/id`) using `VULNERS_API_KEY`,
  - stores the description + metadata (e.g., CVSS score) back into ChromaDB for reuse.
4. **Streaming UX (NDJSON)**
  The `/scan` endpoint streams dictionaries as newline-delimited JSON so the Streamlit UI can render:
  - step logs,
  - tool actions,
  - observations,
  - and the final report.
5. **Persistence**
  Once the agent emits a `final_answer`, the backend persists the result to Postgres (including lightweight manifest metadata describing the run).

### **How Nmap + Vulners + Vulners API Fit Together**

- **Nmap + vulners.nse** provides *service-to-CVE mapping* during scanning (fast, scan-time correlation).
- **Vulners API** provides *CVE description + scoring context* when you need richer narrative detail.
- **ChromaDB** turns that enrichment into reusable memory, reducing repeated API calls and enabling consistent report context across scans.

---

## **Setup & Installation**

### **Prerequisites**

- **Docker Desktop** (recommended path)
- Optional for local dev: **Python 3.10+**

### **Environment Variables**

Create a `.env` file in the repo root (used by `docker-compose.yml`):

```bash
OPENROUTER_API_KEY=your_key_here
OPENROUTER_MODEL=your_model_here
VULNERS_API_KEY=your_vulners_key_here
```

### **Run (Docker Compose)**

From the repo root:

```bash
docker compose up --build
```

This brings up:

- **Frontend (Streamlit)**: `http://localhost:8501`
- **Backend (FastAPI)**: `http://localhost:8000` (health check at `/`)
- **Postgres**: `localhost:5432` (container-internal use; persisted via volume)
- **Chroma persistent storage**: mounted to the backend container (volume `chroma_data`)
- **Sandbox target container**: a deliberately vulnerable target exposed only to the Docker network (no host port publishing)

### **Run (Local Dev, Without Docker)**

If you prefer to run services directly on your machine:

1. Create and activate a virtual environment, then install dependencies from `pyproject.toml` (your preferred tool: `pip`, `uv`, or `poetry`).
2. Set environment variables:

```bash
set OPENROUTER_API_KEY=...
set OPENROUTER_MODEL=...
set VULNERS_API_KEY=...
set DATABASE_URL=postgresql://postgres:postgres@localhost:5432/threatscope
set CHROMA_PERSIST_DIRECTORY=./chroma_data
```

1. Start Postgres (local or via `docker compose up db`).
2. Start the backend:

```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

1. Start the frontend:

```bash
streamlit run frontend/app.py --server.port 8501
```

---

## **Notes on Safety & Scope**

- ThreatScope is intended for **authorized testing only**.
- The project is designed around **read-only observability** and **analysis/reporting**—not automated exploitation or remediation.

