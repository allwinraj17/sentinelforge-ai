import { useState } from 'react'
import './App.css'

const API_URL = 'https://sentinelforge-ai.onrender.com'

function App() {
  const [file, setFile] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [findings, setFindings] = useState(null)
  const [error, setError] = useState(null)

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0]

    if (!selectedFile) return

    if (!selectedFile.name.toLowerCase().endsWith('.zip')) {
      setError('Please select a ZIP file.')
      setFile(null)
      return
    }

    setFile(selectedFile)
    setFindings(null)
    setError(null)
  }

  const handleScan = async () => {
    if (!file) return

    setScanning(true)
    setError(null)
    setFindings(null)

    const formData = new FormData()
    formData.append('file', file)

    try {
      const response = await fetch(`${API_URL}/scan/upload`, {
        method: 'POST',
        body: formData,
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.detail || 'Security scan failed.')
      }

      setFindings(data)
    } catch (err) {
      setError(
        err.message ||
        'Unable to connect to SentinelForge backend.'
      )
    } finally {
      setScanning(false)
    }
  }

  const getSeverity = (finding) => {
    const severity =
      finding?.extra?.severity ||
      finding?.extra?.metadata?.severity

    if (!severity) return 'MEDIUM'

    if (severity === 'ERROR') return 'HIGH'
    if (severity === 'WARNING') return 'MEDIUM'
    if (severity === 'INFO') return 'LOW'

    return severity.toUpperCase()
  }

  const getVulnerabilityName = (finding) => {
    const vulnerabilities =
      finding?.extra?.metadata?.vulnerability_class

    if (Array.isArray(vulnerabilities) && vulnerabilities.length > 0) {
      return vulnerabilities[0]
    }

    return 'Security Vulnerability'
  }

  const getFileName = (path) => {
    if (!path) return 'Unknown file'

    return path.split('/').pop()
  }

  return (
    <div className="app">

      {/* SIDEBAR */}

      <aside className="sidebar">

        <div className="brand">

          <div className="brand-icon">
            🛡
          </div>

          <div>
            <h1>SentinelForge</h1>
            <span>AI Security Platform</span>
          </div>

        </div>

        <nav>

          <div className="nav-item active">
            <span>▣</span>
            Dashboard
          </div>

          <div className="nav-item">
            <span>⌕</span>
            Security Scan
          </div>

          <div className="nav-item">
            <span>▤</span>
            Reports
          </div>

          <div className="nav-item">
            <span>⚙</span>
            Settings
          </div>

        </nav>

        <div className="sidebar-bottom">

          <div className="system-status">

            <span className="status-dot"></span>

            <div>
              <strong>Backend Online</strong>
              <small>Render API connected</small>
            </div>

          </div>

        </div>

      </aside>


      {/* MAIN */}

      <main className="main">

        {/* TOP BAR */}

        <header className="topbar">

          <div>

            <span className="breadcrumb">
              Dashboard / Security Scanner
            </span>

            <h2>Code Security</h2>

          </div>

          <div className="online">
            <span></span>
            Production
          </div>

        </header>


        {/* CONTENT */}

        <section className="content">

          {/* HERO */}

          <div className="hero">

            <div>

              <div className="hero-label">
                SECURITY ANALYSIS
              </div>

              <h3>
                Protect your code before
                <br />
                it reaches production.
              </h3>

              <p>
                Upload a ZIP file and SentinelForge
                will scan your source code for security
                vulnerabilities.
              </p>

            </div>

            <div className="hero-shield">
              🛡
            </div>

          </div>


          {/* UPLOAD */}

          <div className="upload-card">

            <div className="section-title">

              <div>

                <h3>Scan Code</h3>

                <p>
                  Upload your project as a ZIP file
                </p>

              </div>

              <span className="supported">
                ZIP ONLY
              </span>

            </div>


            <label className="drop-zone">

              <input
                type="file"
                accept=".zip"
                onChange={handleFileChange}
                hidden
              />

              <div className="upload-icon">
                ↑
              </div>

              <h4>
                {file
                  ? file.name
                  : 'Drop your ZIP file here'}
              </h4>

              <p>
                {file
                  ? `${(file.size / 1024 / 1024).toFixed(2)} MB`
                  : 'or click to browse files'}
              </p>

            </label>


            <button
              className="scan-button"
              onClick={handleScan}
              disabled={!file || scanning}
            >

              {scanning ? (
                <>
                  <span className="spinner"></span>
                  Scanning Code...
                </>
              ) : (
                <>
                  Start Security Scan
                  <span>→</span>
                </>
              )}

            </button>

          </div>


          {/* ERROR */}

          {error && (

            <div className="error-box">

              <span>!</span>

              <div>

                <strong>Scan Error</strong>

                <p>{error}</p>

              </div>

            </div>

          )}


          {/* RESULTS */}

          {findings && (

            <>

              {/* STATISTICS */}

              <div className="stats">

                <div className="stat-card">

                  <div className="stat-icon">
                    ◉
                  </div>

                  <div>

                    <span>Total Findings</span>

                    <strong>
                      {findings.findings_count}
                    </strong>

                  </div>

                </div>


                <div className="stat-card danger">

                  <div className="stat-icon">
                    !
                  </div>

                  <div>

                    <span>High Risk</span>

                    <strong>
                      {
                        findings.findings.filter(
                          (f) =>
                            getSeverity(f) === 'HIGH'
                        ).length
                      }
                    </strong>

                  </div>

                </div>


                <div className="stat-card">

                  <div className="stat-icon">
                    #
                  </div>

                  <div>

                    <span>Files Affected</span>

                    <strong>
                      {
                        new Set(
                          findings.findings.map(
                            (f) => f.path
                          )
                        ).size
                      }
                    </strong>

                  </div>

                </div>


                <div className="stat-card">

                  <div className="stat-icon">
                    ✓
                  </div>

                  <div>

                    <span>Scanner</span>

                    <strong>
                      Semgrep
                    </strong>

                  </div>

                </div>

              </div>


              {/* FINDINGS */}

              <div className="findings-section">

                <div className="section-title">

                  <div>

                    <h3>
                      Security Findings
                    </h3>

                    <p>
                      Detected vulnerabilities in{' '}
                      <strong>
                        {findings.filename}
                      </strong>
                    </p>

                  </div>

                  <span className="finding-count">
                    {findings.findings_count} Findings
                  </span>

                </div>


                {findings.findings.length === 0 ? (

                  <div className="no-findings">

                    <div>✓</div>

                    <h3>
                      No vulnerabilities detected
                    </h3>

                    <p>
                      Your code passed the current
                      security checks.
                    </p>

                  </div>

                ) : (

                  <div className="finding-list">

                    {findings.findings.map(
                      (finding, index) => {

                        const severity =
                          getSeverity(finding)

                        const name =
                          getVulnerabilityName(
                            finding
                          )

                        return (

                          <div
                            className="finding-card"
                            key={index}
                          >

                            <div className="finding-severity">

                              {severity === 'HIGH'
                                ? '!'
                                : '•'}

                            </div>


                            <div className="finding-main">

                              <div className="finding-heading">

                                <h4>
                                  {name}
                                </h4>

                                <span
                                  className={`severity ${severity.toLowerCase()}`}
                                >
                                  {severity}
                                </span>

                              </div>


                              <p className="finding-message">

                                {
                                  finding.extra?.message ||
                                  'Security vulnerability detected.'
                                }

                              </p>


                              <div className="finding-meta">

                                <span>
                                  📄{' '}
                                  {getFileName(
                                    finding.path
                                  )}
                                </span>

                                <span>
                                  Line{' '}
                                  {finding.start?.line ||
                                    '-'}
                                </span>

                                <span>
                                  CWE-89
                                </span>

                              </div>

                            </div>


                            <div className="finding-arrow">
                              →
                            </div>

                          </div>

                        )

                      }
                    )}

                  </div>

                )}

              </div>

            </>

          )}

        </section>

      </main>

    </div>
  )
}

export default App