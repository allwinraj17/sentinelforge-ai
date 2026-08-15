import { useState } from 'react'
import './App.css'

const API_URL = 'https://sentinelforge-ai.onrender.com'

function App() {
  const [file, setFile] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [findings, setFindings] = useState(null)
  const [error, setError] = useState(null)

  const [showKeyModal, setShowKeyModal] = useState(false)
  const [apiKey, setApiKey] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [analysis, setAnalysis] = useState(null)

  const handleFileChange = (e) => {
    setFile(e.target.files[0])
    setFindings(null)
    setAnalysis(null)
    setError(null)
  }

  const handleScan = async () => {
    if (!file) return
    setScanning(true)
    setError(null)
    setAnalysis(null)

    const formData = new FormData()
    formData.append('file', file)

    try {
      const response = await fetch(`${API_URL}/scan/upload`, {
        method: 'POST',
        body: formData,
      })
      if (!response.ok) throw new Error('Scan failed')
      const data = await response.json()
      setFindings(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setScanning(false)
    }
  }

  const handleAnalyze = async () => {
    if (!apiKey || !findings) return
    setAnalyzing(true)
    setError(null)

    try {
      const response = await fetch(`${API_URL}/scan/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          api_key: apiKey,
          provider: 'gemini',
          findings: findings.findings,
        }),
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.detail || 'Analysis failed')
      setAnalysis(data.analysis)
      setShowKeyModal(false)
      setApiKey('')
    } catch (err) {
      setError(err.message)
    } finally {
      setAnalyzing(false)
    }
  }

  return (
    <div className="app">
      <h1>SentinelForge AI</h1>
      <p className="subtitle">Automated Software Repository Security Analysis</p>

      <div className="upload-section">
        <input type="file" accept=".zip" onChange={handleFileChange} />
        <button onClick={handleScan} disabled={!file || scanning}>
          {scanning ? 'Scanning...' : 'START SECURITY SCAN'}
        </button>
      </div>

      {error && <p className="error">{error}</p>}

      {findings && (
        <div className="results">
          <h2>Scan Results</h2>
          <p>{findings.findings_count} finding(s) in {findings.filename}</p>
          <ul>
            {findings.findings.map((f, i) => (
              <li key={i}>
                <strong>{f.check_id}</strong> — {f.extra?.message} ({f.path}:{f.start?.line})
              </li>
            ))}
          </ul>

          {findings.findings_count > 0 && !analysis && (
            <button onClick={() => setShowKeyModal(true)}>
              Analyze with AI
            </button>
          )}
        </div>
      )}

      {analysis && (
        <div className="analysis">
          <h2>AI Analysis</h2>
          <pre>{analysis}</pre>
        </div>
      )}

      {showKeyModal && (
        <div className="modal-overlay">
          <div className="modal">
            <h3>Enter your Gemini API Key</h3>
            <p className="modal-note">
              Your key is used only for this analysis and is never stored.
            </p>
            <input
              type="password"
              placeholder="AIza..."
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
            />
            <div className="modal-actions">
              <button onClick={() => setShowKeyModal(false)}>Cancel</button>
              <button onClick={handleAnalyze} disabled={!apiKey || analyzing}>
                {analyzing ? 'Analyzing...' : 'Analyze'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default App