import streamlit as st
import requests
import json
import time

# --- Config & Constants ---
# In Docker, 'backend' will resolve to the FastAPI container. 
# We use localhost for fallback if running outside Docker.
BACKEND_URL = "http://backend:8000" 

st.set_page_config(page_title="ThreatScope v0.2", page_icon="🛡️", layout="wide")

# --- UI Header ---
st.title("🛡️ ThreatScope")
st.markdown("**Iteration v0.2: Basic Scanner** - *Read-Only Observability Scanner*")
st.divider()

# --- Sidebar ---
with st.sidebar:
    st.header("Target Configuration")
    target_ip = st.text_input("Target IP / Subnet", value="172.19.0.5")
    run_scan = st.button("Run Agentic Scan", type="primary", use_container_width=True)
    
    st.divider()
    st.caption("Agent Status: Idle")

# --- Main Logic ---
if run_scan:
    if not target_ip:
        st.warning("Please enter a Target IP.")
    else:
        st.info(f"Initiating scan protocol for {target_ip}...")
        
        # UI placeholder for the agent's "thought process"
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Simulate initial agent warmup (UX trick)
        status_text.text("Agent is waking up...")
        time.sleep(1)
        progress_bar.progress(30)
        status_text.text(f"Connecting to orchestrator at {BACKEND_URL}...")
        
        try:
            # Attempt to hit the backend endpoint
            response = requests.post(
                f"{BACKEND_URL}/scan", 
                json={"target_ip": target_ip},
                timeout=120
            )
            response.raise_for_status()
            
            data = response.json()
            progress_bar.progress(100)
            status_text.text("Scan complete.")
            
            # --- Display Results ---
            st.success("Agent returned a verdict!")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Agent Verdict")
                # We expect the dummy backend to return a 'verdict' string
                st.write(data.get("verdict", "No verdict returned."))
                
            with col2:
                st.subheader("Raw Manifest")
                # Display the raw JSON (dummy nmap data)
                st.json(data.get("manifest", {}))

        except requests.exceptions.ConnectionError:
            progress_bar.empty()
            status_text.empty()
            st.error(f"🚨 **Connection Error:** Could not reach the backend at `{BACKEND_URL}`.")
            st.code("Hint: Is the FastAPI container running and mapped to port 8000?", language="markdown")
            
        except Exception as e:
            progress_bar.empty()
            status_text.empty()
            st.error(f"An unexpected error occurred: {e}")