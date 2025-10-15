import React, { useState } from 'react'
const API = import.meta.env.VITE_API_URL || 'http://localhost:8080'

export default function App(){
  const [text,setText] = useState('')
  const [res,setRes] = useState(null)
  const [busy,setBusy] = useState(false)
  const [error,setError] = useState(null)

  const analyze = async () => {
    setBusy(true)
    setRes(null)
    setError(null)
    try {
      const r = await fetch(`${API}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ log_text: text, top_k: 6 })
      })
      if (!r.ok) {
        const txt = await r.text().catch(()=>null)
        throw new Error(`API returned ${r.status} ${r.statusText}${txt ? `: ${txt}` : ''}`)
      }
      const data = await r.json()
      setRes(data)
    } catch (err) {
      console.error('Analyze error', err)
      setError(err.message || String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="container">
      <div className="card">
        <div className="header">
          <div className="logo">IR</div>
          <div>
            <h1>GenAI Incident Assistant</h1>
            <div className="subtitle">Paste a suspicious log line or a small snippet to analyze</div>
          </div>
        </div>

        <div style={{marginTop:14}}>
          <textarea value={text} onChange={e=>setText(e.target.value)} rows={10} placeholder="Paste a suspicious log line or small snippet..." />
        </div>

        <div className="controls">
          <button className="btn" onClick={analyze} disabled={busy || !text.trim()}>{busy ? <span className="spinner" /> : 'Analyze'}</button>
          <button className="btn secondary" onClick={()=>{setText(''); setRes(null); setError(null)}}>Clear</button>
          <div style={{marginLeft:'auto'}} className="muted">Model: <span className="chip">Vite + Ollama</span></div>
        </div>

        {busy && (
          <div className="loading"><span className="spinner" /> Analyzing log…</div>
        )}

        {error && (
          <div className="error">
            <strong>Error:</strong> <span style={{color:'red'}}>{error}</span>
          </div>
        )}

        {res && (
          <div className="result">
            <h3>Summary</h3>
            <pre>{res.summary}</pre>

            <h3>MITRE Matches</h3>
            {res.mitre_matches && res.mitre_matches.length > 0 ? (
              <ul>
                {res.mitre_matches.map((m,i)=>(
                  <li key={m.technique_id + '_' + i}>{m.technique_id} {m.name} [{m.tactic}] — {m.evidence}</li>
                ))}
              </ul>
            ) : (
              <div className="muted">No MITRE matches found.</div>
            )}

            <h3>Related Evidence</h3>
            {res.evidence && res.evidence.length > 0 ? (
              <ol>
                {res.evidence.map((e,i)=>(
                  <li key={(e && e.id) ? e.id : i}>
                    <div>
                      <code className="muted">{e.metadata?.event_type}</code> — {e.text}
                    </div>
                    <div className="muted" style={{fontSize:'0.9em'}}>
                      <span>Source: {e.metadata?.source}</span> | <span>Time: {e.metadata?.ingest_time || e.metadata?.timestamp}</span> | <span>Hash: {e.metadata?.hash}</span>
                    </div>
                  </li>
                ))}
              </ol>
            ) : (
              <div className="muted">No related evidence found. The vector index may be empty or embeddings unavailable.</div>
            )}
          </div>
        )}

        <div className="footer">Running locally — use small snippets (1-6 lines) for best results.</div>
      </div>
    </div>
  )
}
