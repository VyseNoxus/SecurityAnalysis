Testing For Now

# Dataset
https://datasets.uwf.edu/data/UWF-ZeekData22/csv/

# Software Requirements
1. Docker Desktop

# How To Run
1. docker-compose up -d --build
2. docker compose exec ollama bash -lc "ollama pull mistral && ollama pull nomic-embed-text"
3. open http://localhost:3000 [Web UI]

# Understanding files
1. rag.py: Turns log into a vector
2. main.py: Frontend endpoints functions
3. mitre_map.yml: For mapping MITRE ATT&CK techniques
4. check_logs.py: Check for collections in Chroma DB
5. parsers folder: Normalizes a different log type into a consistent JSON structure
