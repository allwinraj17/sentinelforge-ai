import { useState } from 'react'
import './App.css'

function App() {
  const [file, setFile] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [findings, setFindings] = useState(null)
  const [error, setError] = useState(null)

  const handleFileChange = (e) => {
    setFile(e.target.files[0])
    setFindings(null)
    setError(null)
  }

  const handleScan = async () => {
    if (!file) return
    setScanning(true)
    setError(null)

    const formData = new FormData()
    formData.append('file', file)

    try {
      const response = await fetch('http://127.0.0.1:8000/scan/upload', {
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
        </div>
      )}
    </div>
  )
}

export default App