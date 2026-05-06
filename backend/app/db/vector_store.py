import os
import chromadb

# Read persistent directory from env, default to a local folder in the container
PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIRECTORY", "/app/chroma_data")

# Initialize ChromaDB persistent client
chroma_client = chromadb.PersistentClient(path=PERSIST_DIR)

# Get or create the collection for storing CVE details
# We use Chroma's default embedding function under the hood
cve_collection = chroma_client.get_or_create_collection(
    name="cve_knowledge_base",
    metadata={"hnsw:space": "cosine"}
)

def get_collection():
    return cve_collection