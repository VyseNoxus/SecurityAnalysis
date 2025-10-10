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
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,           # keep False if using "*"; True requires explicit origins (we have them)
    allow_methods=["POST", "OPTIONS"], # allow preflight + POST
    allow_headers=["*"],               # allow Content-Type, etc.
)

class IngestBody(BaseModel):
    source: str  # zeek | windows | cloudtrail
    items: List[dict]

class AnalyzeBody(BaseModel):
    log_text: str
    top_k: int = 6

@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.post("/ingest")
async def ingest(body: IngestBody):
    parser = {"zeek": parse_zeek, "windows": parse_win, "cloudtrail": parse_ct}.get(body.source)
    if not parser:
        return {"error": "unknown source"}
    docs = []
    for line in body.items:
        norm = parser(line)
        text = f"{norm.get('timestamp')} {norm.get('event_type')} {norm.get('message')}"
        docs.append({"text": text, "metadata": {"source": body.source, **{k:v for k,v in norm.items() if k!='raw'}}})
    ids = await add_documents(docs)
    return {"ingested": len(ids)}

@app.post("/analyze")
async def analyze(body: AnalyzeBody):
    hits = await search_similar(body.log_text, k=body.top_k)
    llm_out = await generate(body.log_text, hits)
    heur = mitre_match(body.log_text)
    return {
        "summary": llm_out,
        "mitre_matches": heur,
        "evidence": hits
    }
