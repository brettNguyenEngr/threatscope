import os
import json
import requests
from typing import Dict, Any

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

You have access to the following tools:
1. `ping_sweep` - Arguments: {"target_subnet": "string"} (Finds active IPs)
2. `port_scan` - Arguments: {"target_ip": "string"} (Finds open ports)
3. `vulners_scan` - Arguments: {"target_ip": "string", "port_list": [int, int]} (Runs CVE scan on specific ports)
4. `fetch_cve` - Arguments: {"cve_id": "string"} (Looks up the English description of a CVE ID)

You operate in a loop of Thought, Action, Observation.
You MUST respond with a SINGLE valid JSON object at every step. Do not add conversational text outside the JSON.

FORMAT 1 - TO TAKE AN ACTION:
{
    "thought": "I need to see what ports are open on 172.18.0.2.",
    "tool": "port_scan",
    "arguments": {"target_ip": "172.18.0.2"}
}

FORMAT 2 - TO FINISH THE INVESTIGATION:
{
    "thought": "I have gathered all necessary information.",
    "final_answer": "# ThreatScope Security Report \\n\\n (Your human-readable markdown report goes here)"
}
"""

def run_agentic_loop(target: str) -> str:
    """
    The main engine. This loops up to 10 times, letting the LLM choose tools 
    and feeding the observations back to it until it issues a 'final_answer'.
    """
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Begin your investigation on the target: {target}"}
    ]
    
    api_key = os.getenv("OPENROUTER_API_KEY")
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    
    print(f"\n🚀 --- AGENT SPAWNED FOR TARGET: {target} ---")
    
    max_steps = 10
    for step in range(max_steps):
        print(f"\n🧠 [Step {step+1}] Agent is thinking...")
        
        payload = {
            "model": os.getenv("OPENROUTER_MODEL"),
            "messages": messages,
            "temperature": 0.1
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload).json()
        except Exception as e:
            return f"Error contacting LLM API: {e}"
        
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
            print(f"⚠️ Unexpected API Response: {response}")
            break
        except json.JSONDecodeError as e:
            print(f"⚠️ Agent generated invalid JSON.\nRaw: {raw_content}\nError: {e}")
            break
            
        print(f"💭 Thought: {agent_decision.get('thought', 'No thought provided')}")
        
        # 2. Check if the Agent is done
        if "final_answer" in agent_decision:
            print("✅ Agent reached a conclusion!")
            return agent_decision["final_answer"]
            
        # 3. The Agent wants to use a tool
        tool_name = agent_decision.get("tool")
        tool_args = agent_decision.get("arguments", {})
        
        if tool_name in AVAILABLE_TOOLS:
            print(f"🛠️  Action: Executing `{tool_name}` with args {tool_args}...")
            
            tool_function = AVAILABLE_TOOLS[tool_name]
            try:
                # Type safety check before unpacking kwargs
                if not isinstance(tool_args, dict):
                    print("⚠️ Warning: Agent provided non-dictionary arguments. Coercing to empty dict.")
                    tool_args = {}
                    
                observation = tool_function(**tool_args)
            except Exception as e:
                observation = f"Error executing tool: {str(e)}"
                
            print(f"👁️  Observation: {observation}")
            
            # 4. Feed the observation back to the Agent's memory
            messages.append({"role": "assistant", "content": raw_content})
            messages.append({"role": "user", "content": f"Observation: {observation}"})
            
        else:
            print(f"⚠️ Agent tried to use a non-existent tool: {tool_name}")
            messages.append({"role": "assistant", "content": raw_content})
            messages.append({"role": "user", "content": f"Observation: Tool '{tool_name}' does not exist. Please use a valid tool."})

    return "Agent terminated: Exceeded maximum steps without reaching a final answer."