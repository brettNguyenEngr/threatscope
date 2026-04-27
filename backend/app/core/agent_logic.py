import argparse
import json
import os
import requests
from dotenv import load_dotenv

load_dotenv()

def assign_verdict(claim, web_evidence):
    url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1") + "/chat/completions"
    evidence_text = json.dumps(web_evidence)
    prompt = f"""Evaluate this claim based on the provided web evidence.
Claim: {claim}
Evidence: {evidence_text}

Respond with ONLY ONE of the following words: supports, contradicts, or insufficient"""

    headers = {"Authorization": f"Bearer {os.getenv('OPENROUTER_API_KEY')}", "Content-Type": "application/json"}
    payload = {"model": os.getenv("OPENROUTER_MODEL"), "messages": [{"role": "user", "content": prompt}]}
    
    response = requests.post(url, headers=headers, json=payload).json()
    verdict = response['choices'][0]['message']['content'].strip().lower()
    
    # Rule-based guardrail
    if "supports" in verdict: return "supports"
    if "contradicts" in verdict: return "contradicts"
    return "insufficient evidence"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    with open(args.input, "r") as f:
        data = json.load(f)

    for item in data["items"]:
        if not item.get("web_evidence"):
            item["verdict"] = "insufficient evidence"
        else:
            item["verdict"] = assign_verdict(item["item_text"], item["web_evidence"])

    with open(args.output, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Agent verification complete. Output saved to {args.output}")

if __name__ == "__main__":
    main()