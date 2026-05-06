import streamlit as st
import requests
import json

# --- Config & Constants ---
# In Docker, 'backend' will resolve to the FastAPI container. 
BACKEND_URL = "http://backend:8000" 

st.set_page_config(page_title="ThreatScope v0.4", page_icon="🛡️", layout="wide")

# --- UI Header ---
st.title("🛡️ ThreatScope")
st.markdown("**Iteration v0.4: Agentic ReAct Loop & RAG** - *Live Streaming Agent*")
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
        
        # 1. Create UI elements to hold our streaming data
        terminal_expander = st.expander("Terminal Logs (Live Agent Thinking)", expanded=True)
        log_placeholder = terminal_expander.empty()
        
        # Container for the final report to appear below the terminal
        report_container = st.container()
        
        terminal_text = ""
        
        try:
            # 2. Open a streaming connection to the backend
            # Note the stream=True parameter! This keeps the connection open.
            with requests.post(f"{BACKEND_URL}/scan", json={"target_ip": target_ip}, stream=True, timeout=300) as response:
                response.raise_for_status()
                
                # 3. Iterate over the NDJSON lines as they arrive from FastAPI
                for line in response.iter_lines():
                    if line:
                        # Decode the bytes into a string, then parse the JSON
                        data = json.loads(line.decode('utf-8'))
                        event_type = data.get("type")
                        content = data.get("content", "")
                        
                        if event_type == "final_answer":
                            st.success("✅ Agent successfully reached a verdict!")
                            report_container.subheader("📝 Final Security Report")
                            report_container.markdown("---")
                            report_container.markdown(content)
                            report_container.markdown("---")
                        else:
                            # For logs and errors, append the text to our "terminal" string
                            terminal_text += content + "\n"
                            # Re-render the markdown block with the updated text
                            log_placeholder.markdown(f"```text\n{terminal_text}\n```")
                            
        except requests.exceptions.Timeout:
            st.error("⏳ **Timeout:** The agent took too long to respond. Check the backend Docker logs.")
            
        except requests.exceptions.ConnectionError:
            st.error(f"🚨 **Connection Error:** Could not reach the backend at `{BACKEND_URL}`.")
            st.code("Hint: Is the FastAPI container running and mapped to port 8000?", language="markdown")
            
        except Exception as e:
            st.error(f"An unexpected error occurred: {e}")