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
    You are an expert cybersecurity analyst. Review the following raw Nmap scan data, which includes CVE findings from the Vulners script.
    Explain these vulnerabilities to a user in a clear, concise, human-readable markdown report. Highlight the most critical issues.
    
    Raw Scan Data:
    {json.dumps(manifest_data, indent=2)}
    """
    
    payload = {
        "model": "meta-llama/llama-3-8b-instruct:free", # Using a free tier model for testing
        "messages": [{"role": "user", "content": prompt}]
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()['choices'][0]['message']['content']
    except Exception as e:
        return f"🚨 **LLM API Error:** Could not generate report. Details: {e}"