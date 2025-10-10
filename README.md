Testing For Now

# Software Requirements
1. Ollama Mistral:latest
2. Docker Desktop

# How To Run
1. docker-compose up -d --build
2. docker compose exec ollama bash -lc "ollama pull mistral && ollama pull nomic-embed-text"
3. open http://localhost:5173 [Web UI]

# Understanding files
1. rag.py: Turns log into a vector
2. mitre_map.yml: For mapping MITRE ATT&CK techniques
3. parsers folder: Normalizes a different log type into a consistent JSON structure