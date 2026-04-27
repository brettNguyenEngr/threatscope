import argparse
import os
from pypdf import PdfReader
import chromadb
from sentence_transformers import SentenceTransformer
from dotenv import load_dotenv

load_dotenv()

def chunk_text(text, chunk_size, chunk_overlap):
    chunks = []
    start = 0
    while start < len(text):
        chunks.append(text[start:start + chunk_size])
        start += chunk_size - chunk_overlap
    return chunks

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pdf", required=True, help="Path to PDF file")
    parser.add_argument("--filing_id", required=True, help="Unique identifier for the filing")
    args = parser.parse_args()

    # Read PDF
    reader = PdfReader(args.pdf)
    text = ""
    for page in reader.pages:
        text += page.extract_text() + "\n"

    # Chunk text
    chunk_size = int(os.getenv("CHUNK_SIZE", 800))
    chunk_overlap = int(os.getenv("CHUNK_OVERLAP", 150))
    chunks = chunk_text(text, chunk_size, chunk_overlap)

    # Embed and Store
    model = SentenceTransformer(os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2"))
    embeddings = model.encode(chunks).tolist()

    client = chromadb.PersistentClient(path="./ai_pipeline/vector_store")
    collection = client.get_or_create_collection("sec_filings")

    ids = [f"{args.filing_id}::{i}" for i in range(len(chunks))]
    metadatas = [{"filing_id": args.filing_id, "pdf_filename": os.path.basename(args.pdf), "chunk_index": i} for i in range(len(chunks))]

    collection.add(documents=chunks, embeddings=embeddings, metadatas=metadatas, ids=ids)
    print(f"Successfully ingested {len(chunks)} chunks for filing {args.filing_id}")

if __name__ == "__main__":
    main()