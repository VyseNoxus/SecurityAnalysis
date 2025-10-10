up:
\tdocker compose up -d --build

down:
\tdocker compose down -v

pull-models:
\tdocker compose exec ollama bash -lc "ollama pull $(GEN_MODEL) && ollama pull $(EMBED_MODEL)"

seed:
\tpython3 - <<'PY'\nimport json,requests,os\napi=f"http://localhost:{os.getenv('API_PORT','8080')}"\nfor name in ['zeek_conn','windows_events','cloudtrail']:\n  path=f'./data/samples/{name}.jsonl'\n  items=[json.loads(l) for l in open(path)]\n  r=requests.post(api+'/ingest', json={'source': name.split('_')[0], 'items':items})\n  print(name, r.status_code, r.text)\nPY
