import streamlit as st
import requests
import json
import time

# --- Config & Constants ---
# In Docker, 'backend' will resolve to the FastAPI container. 
# We use localhost for fallback if running outside Docker.
BACKEND_URL = "http://backend:8000" 

st.set_page_config(page_title="ThreatScope v0.4", page_icon="🛡️", layout="wide")

# --- UI Header ---
st.title("🛡️ ThreatScope")
st.markdown("**Iteration v0.4: Agentic ReAct Loop & RAG** - *Read-Only Observability Scanner*")
st.divider()

# --- Sidebar ---
with st.sidebar:
    st.header("Target Configuration")
    target_ip = st.text_input("Target IP / Subnet", value="172.18.0.3")
    run_scan = st.button("Run Autonomous Agent", type="primary", use_container_width=True)
    
    st.divider()
    st.caption("Agent Status: Idle")

# --- Main Logic ---
if run_scan:
    if not target_ip:
        st.warning("Please enter a Target IP.")
    else:
        st.info(f"Initiating agentic scan protocol for {target_ip}...")
        
        # UI placeholder for the agent's "thought process"
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Simulate initial agent warmup (UX trick)
        status_text.text("Agent is waking up and evaluating target...")
        time.sleep(1)
        progress_bar.progress(30)
        status_text.text(f"Connecting to orchestrator at {BACKEND_URL}. Please wait (this may take 2-3 minutes)...")
        
        try:
            # Attempt to hit the backend endpoint
            # Timeout increased to 5 minutes to allow the agent's ReAct loop to finish
            response = requests.post(
                f"{BACKEND_URL}/scan", 
                json={"target_ip": target_ip},
                timeout=300
            )
            response.raise_for_status()
            
            data = response.json()
            progress_bar.progress(100)
            status_text.text("Investigation complete.")
            
            # --- Display Results ---
            st.success("✅ Agent successfully reached a verdict!")
            
            st.subheader("📝 Final Security Report")
            st.markdown("---")
            # The v0.4 backend returns the final markdown in the 'report' key
            st.markdown(data.get("report", "No report was generated."))
            st.markdown("---")

        except requests.exceptions.Timeout:
            progress_bar.empty()
            status_text.empty()
            st.error("⏳ **Timeout:** The agent took too long to respond. Check the backend Docker logs to see if it is still running.")
            
        except requests.exceptions.ConnectionError:
            progress_bar.empty()
            status_text.empty()
            st.error(f"🚨 **Connection Error:** Could not reach the backend at `{BACKEND_URL}`.")
            st.code("Hint: Is the FastAPI container running and mapped to port 8000?", language="markdown")
            
        except Exception as e:
            progress_bar.empty()
            status_text.empty()
            st.error(f"An unexpected error occurred: {e}")