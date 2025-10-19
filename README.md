Testing For Now

# Dataset
https://datasets.uwf.edu/data/UWF-ZeekData22/csv/

# Software Requirements
1. Ollama Mistral:latest
2. Docker Desktop

# How To Run
1. docker-compose up -d --build
2. docker compose exec ollama bash -lc "ollama pull mistral && ollama pull nomic-embed-text"
3. open http://localhost:3000 [Web UI]

# Understanding files
1. rag.py: Turns log into a vector
2. mitre_map.yml: For mapping MITRE ATT&CK techniques
3. parsers folder: Normalizes a different log type into a consistent JSON structure

# env file
# URLs the services use to talk to each other
OLLAMA_HOST=http://ollama:11434
CHROMA_HOST=http://chroma:8000
API_PORT=8080
WEB_PORT=5173

# Models (pull them after containers start)
GEN_MODEL=mistral
EMBED_MODEL=all-minilm

# Chroma collection name
CHROMA_COLLECTION=ir_logs
