import os
import json
import requests
from typing import Dict, Any, Generator
from datetime import datetime

from app.scanner.nmap_runner import tool_ping_sweep, tool_port_scan, tool_vulners_scan
from app.core.rag_engine import fetch_cve_details

# 1. Register the Agent's Toolbox
AVAILABLE_TOOLS = {
    "ping_sweep": tool_ping_sweep,
    "port_scan": tool_port_scan,
    "vulners_scan": tool_vulners_scan,
    "fetch_cve": fetch_cve_details
}

# 2. The Agent's Constitution
SYSTEM_PROMPT = """
You are ThreatScope, an autonomous cybersecurity agent. 
Your goal is to investigate a target network or IP, identify vulnerabilities, lookup CVE details, and write a final report.

CRITICAL RULES OF ENGAGEMENT:
1. You are lazy if you just dump CVE IDs. You MUST use the `fetch_cve` tool to look up the specific descriptions for the top 3 most critical vulnerabilities for EACH open port BEFORE writing your final report.
2. Do NOT write your final report until you have successfully executed `fetch_cve` on the most dangerous looking CVEs.

You have access to the following tools:
1. `ping_sweep` - Arguments: {"target_subnet": "string"} (Finds active IPs)
2. `port_scan` - Arguments: {"target_ip": "string"} (Finds open ports)
3. `vulners_scan` - Arguments: {"target_ip": "string", "port_list": [int, int]} (Runs CVE scan on specific ports)
4. `fetch_cve` - Arguments: {"cve_id": "string"} (Looks up the English description of a CVE ID)

You operate in a loop of Thought, Action, Observation.
You MUST respond with a SINGLE valid JSON object at every step.

When you are finished gathering data, use FORMAT 2. Your markdown report MUST follow this exact structure:
### Executive Summary
(A brief summary of the total number of vulnerabilities found)

### Port Analysis
(For EACH open port, provide:)
* **Service Description:** (1-2 sentences explaining what the service listening on this port is and why its security matters)
* **Top Vulnerabilities:** (List ONLY the top 3 most critical vulnerabilities found for this port. You MUST include the text description of the CVE you retrieved using the `fetch_cve` tool).

FORMAT 1 - TO TAKE AN ACTION:
{
    "thought": "I need to look up the details for CVE-2011-2523.",
    "tool": "fetch_cve",
    "arguments": {"cve_id": "CVE-2011-2523"}
}

FORMAT 2 - TO FINISH THE INVESTIGATION:
{
    "thought": "I have looked up the details for the top CVEs and am ready to write the report.",
    "final_answer": "# ThreatScope Security Report \\n\\n (Your human-readable markdown report goes here)"
}
"""

def run_agentic_loop(target: str) -> Generator[Dict[str, str], None, None]:
    """
    The main engine. This is now a generator that yields events as dictionaries
    so the frontend can stream the agent's thought process.
    """
    current_date = datetime.now().strftime("%Y-%m-%d")
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Today's date is {current_date}. Begin your investigation on the target: {target}"}
    ]
    
    api_key = os.getenv("OPENROUTER_API_KEY")
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    
    yield {"type": "log", "content": f"🚀 --- AGENT SPAWNED FOR TARGET: {target} ---"}
    
    max_steps = 10
    for step in range(max_steps):
        yield {"type": "log", "content": f"\n🧠 [Step {step+1}] Agent is thinking..."}
        
        payload = {
            "model": os.getenv("OPENROUTER_MODEL"),
            "messages": messages,
            "temperature": 0.1
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload).json()
        except Exception as e:
            yield {"type": "error", "content": f"Error contacting LLM API: {e}"}
            return
        
        raw_content = ""
        try:
            # Safely extract the content
            raw_content = response['choices'][0]['message']['content'].strip()
            
            # Clean up potential markdown formatting block safely
            if raw_content.startswith("```json"):
                raw_content = raw_content[7:]
            if raw_content.endswith("```"):
                raw_content = raw_content[:-3]
            
            raw_content = raw_content.strip()
            agent_decision = json.loads(raw_content)
            
        except KeyError:
            yield {"type": "error", "content": f"⚠️ Unexpected API Response: {response}"}
            break
        except json.JSONDecodeError as e:
            # Fallback handler for raw markdown reports
            if "# ThreatScope" in raw_content or "Executive Summary" in raw_content or "**Target:**" in raw_content:
                yield {"type": "log", "content": "🛡️ Fallback triggered: Agent forgot JSON formatting, but provided a report. Gracefully accepting."}
                agent_decision = {"final_answer": raw_content}
            else:
                yield {"type": "error", "content": f"⚠️ Agent generated invalid JSON.\nRaw: {raw_content}\nError: {e}"}
                break
                
        yield {"type": "log", "content": f"💭 Thought: {agent_decision.get('thought', 'No thought provided')}"}
        
        # 2. Check if the Agent is done
        if "final_answer" in agent_decision:
            yield {"type": "log", "content": "✅ Agent reached a conclusion!"}
            yield {"type": "final_answer", "content": agent_decision["final_answer"]}
            return
            
        # 3. The Agent wants to use a tool
        tool_name = agent_decision.get("tool")
        tool_args = agent_decision.get("arguments", {})
        
        if tool_name in AVAILABLE_TOOLS:
            yield {"type": "log", "content": f"🛠️  Action: Executing `{tool_name}` with args {tool_args}..."}
            
            tool_function = AVAILABLE_TOOLS[tool_name]
            try:
                # Type safety check before unpacking kwargs
                if not isinstance(tool_args, dict):
                    yield {"type": "log", "content": "⚠️ Warning: Agent provided non-dictionary arguments. Coercing to empty dict."}
                    tool_args = {}
                    
                observation = tool_function(**tool_args)
            except Exception as e:
                observation = f"Error executing tool: {str(e)}"
                
            yield {"type": "log", "content": f"👁️  Observation: {observation}"}
            
            # 4. Feed the observation back to the Agent's memory
            messages.append({"role": "assistant", "content": raw_content})
            messages.append({"role": "user", "content": f"Observation: {observation}"})
            
        else:
            yield {"type": "error", "content": f"⚠️ Agent tried to use a non-existent tool: {tool_name}"}
            messages.append({"role": "assistant", "content": raw_content})
            messages.append({"role": "user", "content": f"Observation: Tool '{tool_name}' does not exist. Please use a valid tool."})

    yield {"type": "log", "content": "⚠️ Maximum steps reached. Forcing the agent to compile a final report with available data..."}
    
    # Inject a strict system override into the agent's memory
    messages.append({
        "role": "user", 
        "content": "SYSTEM OVERRIDE: You have reached the maximum allowed actions. You MUST immediately reply with a JSON object containing your 'final_answer' formatted as a markdown security report summarizing all findings so far. Do not use any more tools."
    })
    
    payload = {
        "model": os.getenv("OPENROUTER_MODEL"),
        "messages": messages,
        "temperature": 0.1
    }
    
    try:
        # Make one final API call
        response = requests.post(url, headers=headers, json=payload).json()
        raw_content = response['choices'][0]['message']['content'].strip()
        
        # Clean markdown formatting if present
        if raw_content.startswith("```json"): 
            raw_content = raw_content[7:]
        if raw_content.endswith("```"): 
            raw_content = raw_content[:-3]
        raw_content = raw_content.strip()
        
        try:
            agent_decision = json.loads(raw_content)
            final_report = agent_decision.get("final_answer", raw_content)
        except json.JSONDecodeError:
            # If it still messes up the JSON, just use the raw text as the report
            final_report = raw_content
            
        yield {"type": "log", "content": "✅ Agent successfully forced a conclusion!"}
        yield {"type": "final_answer", "content": final_report}
        
    except Exception as e:
        yield {"type": "error", "content": f"Agent failed to generate forced final report: {e}"}