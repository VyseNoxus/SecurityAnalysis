
# Imports
import os
import uuid
import httpx
import asyncio
import yaml
from typing import List, Dict, Any
import chromadb
from chromadb.config import Settings

# Config
_ollama_env = os.getenv("OLLAMA_HOST", "http://ollama:11434")
OLLAMA = _ollama_env if _ollama_env.startswith(("http://", "https://")) else "http://" + _ollama_env
GEN_MODEL = os.getenv("GEN_MODEL", "mistral")
EMBED_MODEL = os.getenv("EMBED_MODEL", "nomic-embed-text")

_chroma_env = os.getenv("CHROMA_HOST", "chroma:8000")
if ":" in _chroma_env:
    CHROMA_HOST, CHROMA_PORT = _chroma_env.split(":", 1)
    CHROMA_PORT = int(CHROMA_PORT)
else:
    CHROMA_HOST = _chroma_env
    CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))
COLLECTION = os.getenv("CHROMA_COLLECTION", "ir_logs")
client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT, settings=Settings(allow_reset=True))

# Evidence collection
def get_collection():
    try:
        return client.get_collection(COLLECTION)
    except Exception:
        return client.create_collection(COLLECTION, metadata={"hnsw:space":"cosine"})
collection = get_collection()

# Load MITRE rules
with open(os.path.join(os.path.dirname(__file__), "mitre_map.yml"), "r") as f:
    RULES = yaml.safe_load(f)["rules"]

# Embedding functions
async def embed(text: str) -> List[float]:
    async with httpx.AsyncClient(timeout=60) as session:
        try:
            r = await session.post(f"{OLLAMA}/api/embeddings", json={"model": EMBED_MODEL, "prompt": text})
            r.raise_for_status()
            data = r.json()
            return data["embedding"]
        except Exception as e:
            print(f"[ERROR] Embedding failed for text: {text[:80]}... Error: {e}")
            return []

async def embed_many(texts: List[str]) -> List[List[float]]:
    return await asyncio.gather(*(embed(t) for t in texts))

# Evidence ingestion
async def add_documents(docs: List[Dict[str, Any]]):
    ids = [str(uuid.uuid4()) for _ in docs]
    texts = [d["text"] for d in docs]
    metas = [d["metadata"] for d in docs]
    vectors = await embed_many(texts)
    collection.add(ids=ids, documents=texts, metadatas=metas, embeddings=vectors)
    return ids

# MITRE rules ingestion
async def ingest_mitre_rules():
    mitre_collection_name = "mitre_mappings"
    try:
        mitre_collection = client.get_collection(mitre_collection_name)
    except Exception:
        mitre_collection = client.create_collection(mitre_collection_name, metadata={"hnsw:space":"cosine"})
    docs = []
    for rule in RULES:
        text = f"{rule['id']} {rule['name']} {rule['description']} {' '.join(rule.get('patterns', []))} {' '.join(rule.get('tags', []))}"
        tags = rule.get("tags", [])
        metadata = {
            "technique_id": rule["id"],
            "name": rule["name"],
            "tactic": rule["tactic"],
            "description": rule["description"],
            "tags": ','.join(tags) if isinstance(tags, list) else str(tags)
        }
        docs.append({"text": text, "metadata": metadata})
    ids = [str(uuid.uuid4()) for _ in docs]
    texts = [d["text"] for d in docs]
    metas = [d["metadata"] for d in docs]
    vectors = await embed_many(texts)
    mitre_collection.add(ids=ids, documents=texts, metadatas=metas, embeddings=vectors)
    return len(ids)

# Evidence search
async def search_similar(query: str, k: int = 6):
    try:
        qvec = await embed(query)
    except Exception as e:
        print(f"[ERROR] Embedding failed for query: {query[:80]}... Error: {e}")
        return []
    if not qvec:
        print(f"[ERROR] Empty embedding for query: {query[:80]}...")
        return []
    try:
        res = collection.query(query_embeddings=[qvec], n_results=k)
    except Exception as e:
        print(f"[ERROR] ChromaDB query failed for query: {query[:80]}... Error: {e}")
        return []
    hits = []
    for i in range(len(res["ids"][0])):
        hits.append({
            "id": res["ids"][0][i],
            "text": res["documents"][0][i],
            "metadata": res["metadatas"][0][i],
            "distance": res["distances"][0][i] if "distances" in res else None
        })
    return hits

# MITRE mapping
def mitre_match(text: str) -> List[Dict[str, str]]:
    results = []
    low = text.lower()
    for r in RULES:
        for p in r["patterns"]:
            if p.lower() in low:
                results.append({"technique_id": r["id"], "name": r["name"], "tactic": r["tactic"], "evidence": p})
                break
    seen = set()
    uniq = []
    for item in results:
        key = (item["technique_id"], item["evidence"])
        if key not in seen:
            seen.add(key)
            uniq.append(item)
    return uniq

# LLM prompt and generation
ANALYST_PROMPT = (
    "You are an incident response assistant.\n"
    "Given: (1) a fresh INCIDENT LOG, (2) RELATED EVIDENCE EXCERPTS, produce:\n"
    "- a concise 4-8 line summary of what likely happened,\n"
    "- prioritized next steps (bulleted), concrete and actionable, low-regret.\n"
    "Be concise, cite evidence by [Doc#] where appropriate.\n"
    "IMPORTANT: Do NOT list or enumerate MITRE ATT&CK technique IDs in your response — MITRE matches will be provided separately by a deterministic heuristic."
)

def build_prompt(incident: str, snippets: List[Dict[str, Any]]) -> str:
    ctx = "\n".join([f"[Doc{i+1}] {s['text']}" for i, s in enumerate(snippets)])
    return f"{ANALYST_PROMPT}\n\nINCIDENT LOG:\n{incident}\n\nRELATED EVIDENCE:\n{ctx}\n"

async def generate(incident: str, snippets: List[Dict[str, Any]]):
    prompt = build_prompt(incident, snippets)
    async with httpx.AsyncClient(timeout=120) as session:
        r = await session.post(f"{OLLAMA}/api/generate", json={"model": GEN_MODEL, "prompt": prompt, "stream": False})
        r.raise_for_status()
        return r.json().get("response", "").strip()
