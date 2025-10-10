import os, uuid, httpx, asyncio, yaml
from typing import List, Dict, Any
import chromadb
from chromadb.config import Settings

OLLAMA = os.getenv("OLLAMA_HOST", "http://ollama:11434")
GEN_MODEL = os.getenv("GEN_MODEL", "mistral")
EMBED_MODEL = os.getenv("EMBED_MODEL", "nomic-embed-text")
CHROMA_HOST = os.getenv("CHROMA_HOST", "http://chroma:8000").split("://")[-1].split(":")[0]
CHROMA_PORT = int(os.getenv("CHROMA_HOST", "http://chroma:8000").split(":")[-1])
COLLECTION = os.getenv("CHROMA_COLLECTION", "ir_logs")

client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT, settings=Settings(allow_reset=True))

def get_collection():
    try:
        return client.get_collection(COLLECTION)
    except Exception:
        return client.create_collection(COLLECTION, metadata={"hnsw:space":"cosine"})

collection = get_collection()

with open(os.path.join(os.path.dirname(__file__), "mitre_map.yml"), "r") as f:
    RULES = yaml.safe_load(f)["rules"]

async def embed(text: str) -> List[float]:
    async with httpx.AsyncClient(timeout=60) as session:
        r = await session.post(f"{OLLAMA}/api/embeddings", json={"model": EMBED_MODEL, "input": text})
        r.raise_for_status()
        data = r.json()
        # Ollama returns {"embedding":[...]} for single input
        return data["embedding"]

async def embed_many(texts: List[str]) -> List[List[float]]:
    return [await embed(t) for t in texts]

async def add_documents(docs: List[Dict[str, Any]]):
    ids = [str(uuid.uuid4()) for _ in docs]
    texts = [d["text"] for d in docs]
    metas = [d["metadata"] for d in docs]
    vectors = await embed_many(texts)
    collection.add(ids=ids, documents=texts, metadatas=metas, embeddings=vectors)
    return ids

async def search_similar(query: str, k: int = 6):
    qvec = await embed(query)
    res = collection.query(query_embeddings=[qvec], n_results=k)
    hits = []
    for i in range(len(res["ids"][0])):
        hits.append({
            "id": res["ids"][0][i],
            "text": res["documents"][0][i],
            "metadata": res["metadatas"][0][i],
            "distance": res["distances"][0][i] if "distances" in res else None
        })
    return hits

def mitre_match(text: str) -> List[Dict[str, str]]:
    results = []
    low = text.lower()
    for r in RULES:
        for p in r["patterns"]:
            if p.lower() in low:
                results.append({"technique_id": r["id"], "name": r["name"], "tactic": r["tactic"], "evidence": p})
                break
    # de-duplicate
    seen = set()
    uniq = []
    for item in results:
        key = (item["technique_id"], item["evidence"])
        if key not in seen:
            seen.add(key)
            uniq.append(item)
    return uniq

ANALYST_PROMPT = """You are an incident response assistant.
Given: (1) a fresh INCIDENT LOG, (2) RELATED EVIDENCE EXCERPTS, produce:
- a 4-8 line summary of what likely happened,
- the most relevant MITRE ATT&CK techniques (IDs) with 1-liner rationale for each,
- prioritized next steps (bulleted), concrete and actionable, low-regret.
Be concise, cite evidence by [Doc#] where appropriate.
"""

def build_prompt(incident: str, snippets: List[Dict[str, Any]]) -> str:
    ctx = "\n".join([f"[Doc{i+1}] {s['text']}" for i, s in enumerate(snippets)])
    return f"""{ANALYST_PROMPT}

INCIDENT LOG:
{incident}

RELATED EVIDENCE:
{ctx}
"""

async def generate(incident: str, snippets: List[Dict[str, Any]]):
    prompt = build_prompt(incident, snippets)
    async with httpx.AsyncClient(timeout=120) as session:
        r = await session.post(f"{OLLAMA}/api/generate", json={"model": GEN_MODEL, "prompt": prompt, "stream": False})
        r.raise_for_status()
        return r.json().get("response","").strip()
