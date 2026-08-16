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
    if (!file) {
      setError('Please select a ZIP file first.')
      return
    }

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

      let data

      try {
        data = await response.json()
      } catch {
        throw new Error(
          `Backend returned an invalid response (${response.status}).`
        )
      }

      if (!response.ok) {
        throw new Error(
          data?.detail ||
          data?.message ||
          `Security scan failed (${response.status}).`
        )
      }

      if (!data) {
        throw new Error('The backend returned an empty response.')
      }

      setFindings({
        ...data,
        findings: Array.isArray(data.findings)
          ? data.findings
          : [],
        findings_count:
          typeof data.findings_count === 'number'
            ? data.findings_count
            : Array.isArray(data.findings)
              ? data.findings.length
              : 0,
        risk_assessments: Array.isArray(data.risk_assessments)
          ? data.risk_assessments
          : [],
        overall_risk:
          data.overall_risk || {
            overall_score: 0,
            overall_level: 'SECURE',
            total_findings: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
          },
      })
    } catch (err) {
      console.error('Scan request error:', err)

      if (err instanceof TypeError) {
        setError(
          'Unable to connect to the SentinelForge backend. Please check the backend connection and try again.'
        )
      } else {
        setError(
          err.message ||
          'Unable to complete the security scan.'
        )
      }
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

    if (
      Array.isArray(vulnerabilities) &&
      vulnerabilities.length > 0
    ) {
      return vulnerabilities[0]
    }

    return 'Security Vulnerability'
  }

  const getFileName = (path) => {
    if (!path) return 'Unknown file'

    return path.split('/').pop()
  }

  const getRiskClass = (level) => {
    if (!level) return 'medium'

    return level.toLowerCase()
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

              {/* PHASE 2 RISK OVERVIEW */}

              {findings.overall_risk && (

                <div className="risk-overview">

                  <div className="risk-overview-header">

                    <div>

                      <span className="hero-label">
                        RISK ASSESSMENT
                      </span>

                      <h3>
                        Overall Security Risk
                      </h3>

                    </div>

                    <div
                      className={`overall-risk-badge ${getRiskClass(
                        findings.overall_risk.overall_level
                      )}`}
                    >
                      {findings.overall_risk.overall_level}
                    </div>

                  </div>


                  <div className="risk-score">

                    <div className="risk-score-number">
                      {findings.overall_risk.overall_score}
                    </div>

                    <div className="risk-score-label">
                      / 10 Risk Score
                    </div>

                  </div>


                  <div className="risk-breakdown">

                    <div>
                      <span>Critical</span>
                      <strong>
                        {findings.overall_risk.critical}
                      </strong>
                    </div>

                    <div>
                      <span>High</span>
                      <strong>
                        {findings.overall_risk.high}
                      </strong>
                    </div>

                    <div>
                      <span>Medium</span>
                      <strong>
                        {findings.overall_risk.medium}
                      </strong>
                    </div>

                    <div>
                      <span>Low</span>
                      <strong>
                        {findings.overall_risk.low}
                      </strong>
                    </div>

                  </div>

                </div>

              )}


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

                        const assessment =
                          findings.risk_assessments?.[index]

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


                              {/* PHASE 2 DETAILS */}

                              {assessment && (

                                <div className="risk-details">

                                  <div className="risk-detail">

                                    <span>
                                      Risk Score
                                    </span>

                                    <strong>
                                      {assessment.risk_score}/10
                                    </strong>

                                  </div>


                                  <div className="risk-detail">

                                    <span>
                                      Exploitability
                                    </span>

                                    <strong>
                                      {assessment.exploitability}
                                    </strong>

                                  </div>


                                  <div className="risk-detail-wide">

                                    <span>
                                      Impact
                                    </span>

                                    <p>
                                      {assessment.impact}
                                    </p>

                                  </div>


                                  <div className="risk-detail-wide">

                                    <span>
                                      Recommendation
                                    </span>

                                    <p>
                                      {assessment.recommendation}
                                    </p>

                                  </div>

                                </div>

                              )}


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
                                  {
                                    assessment?.cwe ||
                                    'Security'
                                  }
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