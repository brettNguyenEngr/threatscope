import os
import requests
import json

def generate_verdict(manifest_data: dict) -> str:
    """
    Takes the raw Nmap/Vulners JSON, sends it to OpenRouter, 
    and asks the LLM to explain the vulnerabilities to a user.
    """
    api_key = os.getenv("OPENROUTER_API_KEY")
    
    if not api_key:
        return "⚠️ **System Error:** `OPENROUTER_API_KEY` is missing. Cannot generate verdict."

    # Using a fast, smart model suitable for analysis
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    prompt = f"""
    You are an expert, concise cybersecurity analyst.
    RULES:
    1. If no open ports or vulnerabilities are found, reply with exactly one short paragraph stating the host appears secure/unresponsive on scanned ports. DO NOT invent findings.
    2. If vulnerabilities are found, list the top 3 most critical CVEs using bullet points.
    3. Keep the total response under 150 words. Do not include fluff, generic advice, or disclaimers.
    
    Raw Scan Data:
    {json.dumps(manifest_data, indent=2)}
    """
    
    payload = {
        "model": os.getenv("OPENROUTER_MODEL"),
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 300,
        "temperature": 0.2
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()['choices'][0]['message']['content']
    except Exception as e:
        return f"🚨 **LLM API Error:** Could not generate report. Details: {e}"