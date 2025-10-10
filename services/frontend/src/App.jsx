import React, { useState } from 'react'
const API = import.meta.env.VITE_API_URL || 'http://localhost:8080'

export default function App(){
  const [text,setText] = useState('')
  const [res,setRes] = useState(null)
  const [busy,setBusy] = useState(false)

  const analyze = async () => {
    setBusy(true); setRes(null)
    const r = await fetch(`${API}/analyze`, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ log_text: text, top_k: 6 })
    })
    setRes(await r.json()); setBusy(false)
  }

  return (
    <div style={{maxWidth:900, margin:'2rem auto', fontFamily:'ui-sans-serif'}}>
      <h1>GenAI-Driven Incident Response Assistant</h1>
      <textarea value={text} onChange={e=>setText(e.target.value)} rows={10} style={{width:'100%'}} placeholder="Paste a suspicious log line or small snippet..." />
      <div style={{marginTop:12}}>
        <button onClick={analyze} disabled={busy || !text.trim()}>{busy ? 'Analyzing…' : 'Analyze'}</button>
      </div>
      {res && (
        <div style={{marginTop:24}}>
          <h3>Summary</h3>
          <pre style={{whiteSpace:'pre-wrap'}}>{res.summary}</pre>
          <h3>MITRE Matches (heuristic)</h3>
          <ul>
            {res.mitre_matches?.map((m,i)=><li key={i}>{m.technique_id} {m.name} [{m.tactic}] via “{m.evidence}”</li>)}
          </ul>
          <h3>Related Evidence</h3>
          <ol>
            {res.evidence?.map((e,i)=><li key={e.id}><code>{e.metadata?.event_type}</code> — {e.text}</li>)}
          </ol>
        </div>
      )}
    </div>
  )
}
