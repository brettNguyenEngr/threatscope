import argparse
import os
import json
import requests
import chromadb
from sentence_transformers import SentenceTransformer
from dotenv import load_dotenv

load_dotenv()

def call_llm(prompt):
    url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {os.getenv('OPENROUTER_API_KEY')}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": os.getenv("OPENROUTER_MODEL"),
        "messages": [{"role": "user", "content": prompt}]
    }
    response = requests.post(url, headers=headers, json=payload)
    response_json = response.json()
    
    # Check if the API returned an error instead of a normal response
    if 'choices' not in response_json:
        print(f"--- API ERROR ---\n{json.dumps(response_json, indent=2)}\n-----------------")
        raise KeyError("Failed to get a valid response from OpenRouter. See the API Error above.")
        
    return response_json['choices'][0]['message']['content']

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", required=True, choices=["summary", "risks"])
    parser.add_argument("--filing_id", required=True)
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args()

    # Retrieve chunks
    model = SentenceTransformer(os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2"))
    query_embedding = model.encode([f"What are the {args.task}?"]).tolist()

    client = chromadb.PersistentClient(path="./ai_pipeline/vector_store")
    collection = client.get_or_create_collection("sec_filings")
    
    results = collection.query(
        query_embeddings=query_embedding,
        n_results=int(os.getenv("RAG_TOP_K", 6)),
        where={"filing_id": args.filing_id}
    )

    evidence_text = "\n\n".join(results['documents'][0])
    evidence_list = [{"id": id, "text": doc} for id, doc in zip(results['ids'][0], results['documents'][0])]

    # Load prompt
    with open(f"ai_pipeline/prompts/{args.task}.md", "r") as f:
        prompt_template = f.read()
    
    prompt = prompt_template.replace("{evidence}", evidence_text)
    answer = call_llm(prompt)

    if args.format == "json":
        output = {
            "task": args.task,
            "filing_id": args.filing_id,
            "answer": answer,
            "evidence": evidence_list
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"--- {args.task.upper()} ---\n{answer}\n\n--- EVIDENCE ---\n{evidence_text}")

if __name__ == "__main__":
    main()