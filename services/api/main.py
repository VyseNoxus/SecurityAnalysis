import os, json, asyncio
from typing import List, Optional
from fastapi import FastAPI, UploadFile, File, Body
from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel
from rag import add_documents, search_similar, generate, mitre_match

from parsers.zeek import parse_line as parse_zeek
from parsers.windows import parse_line as parse_win
from parsers.cloudtrail import parse_line as parse_ct

app = FastAPI(title="GenAI Incident Assistant", version="0.1.0")

# Allow the Vite dev server
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,           # keep False if using "*"; True requires explicit origins (we have them)
    allow_methods=["POST", "OPTIONS"], # allow preflight + POST
    allow_headers=["*"],               # allow Content-Type, etc.
)

class IngestBody(BaseModel):
    source: Optional[str] = None  # Optional, will auto-detect if not provided
    items: List[dict]

    class Config:
        extra = "allow"

class AnalyzeBody(BaseModel):
    log_text: str
    top_k: int = 6

@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.post("/ingest")
async def ingest(body: IngestBody):
    def detect_parser(line):
        # Heuristic: check for unique keys
        if any(k in line for k in ["eventName", "userIdentity", "eventTime"]):
            return "cloudtrail", parse_ct
        if any(k in line for k in ["EventID", "TimeCreated", "ProcessName"]):
            return "windows", parse_win
        if any(k in line for k in ["ts", "id.orig_h", "id.resp_h", "proto"]):
            return "zeek", parse_zeek
        # Fallback: try all parsers, pick the one with most non-null fields
        candidates = [
            ("cloudtrail", parse_ct(line)),
            ("windows", parse_win(line)),
            ("zeek", parse_zeek(line)),
        ]
        best = max(candidates, key=lambda x: sum(v is not None for v in x[1].values()))
        return best[0], {"cloudtrail": parse_ct, "windows": parse_win, "zeek": parse_zeek}[best[0]]

    docs = []
    seen = set()
    import hashlib, datetime
    import logging
    for line in body.items:
        # Always ensure line is a dict
        if isinstance(line, str):
            try:
                line = json.loads(line)
            except Exception as e:
                logging.warning(f"Skipped unparseable log line: {line} ({e})")
                continue
        if not isinstance(line, dict):
            logging.warning(f"Skipped non-dict log line: {line}")
            continue
        src = body.source
        parser = None
        if src:
            parser = {"zeek": parse_zeek, "windows": parse_win, "cloudtrail": parse_ct}.get(src)
        if not parser:
            src, parser = detect_parser(line)
        try:
            norm = parser(line)
        except Exception as e:
            logging.warning(f"Parser error for line: {line} ({e})")
            continue
        text = f"{norm.get('timestamp')} {norm.get('event_type')} {norm.get('message')}"
        if text in seen:
            continue
        seen.add(text)
        hashval = hashlib.sha256(text.encode()).hexdigest()
        now = datetime.datetime.utcnow().isoformat() + 'Z'
        metadata = {"source": src, "ingest_time": now, "hash": hashval, **{k:v for k,v in norm.items() if k!='raw' and v is not None}}
        docs.append({"text": text, "metadata": metadata})
    ids = await add_documents(docs)
    return {"ingested": len(ids)}

@app.post("/analyze")
async def analyze(body: AnalyzeBody):
    hits = await search_similar(body.log_text, k=body.top_k)
    llm_out = await generate(body.log_text, hits)
    heur = mitre_match(body.log_text)

    # Semantic MITRE retrieval
    from rag import client, embed, RULES
    try:
        # Use the mitre_mappings collection
        mitre_collection = client.get_collection("mitre_mappings")
    except Exception:
        mitre_collection = None
    semantic_matches = []
    if mitre_collection:
        try:
            qvec = await embed(body.log_text)
            if qvec:
                res = mitre_collection.query(query_embeddings=[qvec], n_results=3)
                for i in range(len(res["ids"][0])):
                    meta = res["metadatas"][0][i]
                    semantic_matches.append({
                        "technique_id": meta.get("technique_id"),
                        "name": meta.get("name"),
                        "tactic": meta.get("tactic"),
                        "description": meta.get("description"),
                        "tags": meta.get("tags", []),
                        "evidence": res["documents"][0][i],
                        "distance": res["distances"][0][i] if "distances" in res else None
                    })
        except Exception as e:
            pass

    # Combine and deduplicate
    all_matches = heur.copy()
    for sm in semantic_matches:
        if not any(h["technique_id"] == sm["technique_id"] and h["evidence"] == sm["evidence"] for h in heur):
            all_matches.append(sm)

    return {
        "summary": llm_out,
        "mitre_matches": all_matches,
        "evidence": hits
    }



