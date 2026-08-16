import { useState } from 'react'
import './App.css'

const API_URL = 'https://sentinelforge-ai.onrender.com'

function App() {
  const [file, setFile] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [findings, setFindings] = useState(null)
  const [error, setError] = useState(null)

  // ============================================================
  // FILE SELECTION
  // ============================================================

  const handleFileChange = (e) => {
    const selectedFile = e.target.files?.[0]

    if (!selectedFile) {
      return
    }

    if (!selectedFile.name.toLowerCase().endsWith('.zip')) {
      setError('Please select a ZIP file.')
      setFile(null)
      setFindings(null)
      return
    }

    setFile(selectedFile)
    setFindings(null)
    setError(null)
  }

  // ============================================================
  // SECURITY SCAN
  // ============================================================

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

      // ----------------------------------------------------------
      // Normalize backend response
      // ----------------------------------------------------------

      const normalizedFindings = Array.isArray(data.findings)
        ? data.findings
        : []

      const normalizedRiskAssessments = Array.isArray(
        data.risk_assessments
      )
        ? data.risk_assessments
        : []

      const normalizedOverallRisk = data.overall_risk || {
        overall_score: 0,
        overall_level: 'SECURE',
        total_findings: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      }

      setFindings({
        ...data,

        findings: normalizedFindings,

        findings_count:
          typeof data.findings_count === 'number'
            ? data.findings_count
            : normalizedFindings.length,

        risk_assessments: normalizedRiskAssessments,

        overall_risk: normalizedOverallRisk,
      })
    } catch (err) {
      console.error('Scan request error:', err)

      if (
        err instanceof TypeError ||
        err?.message?.toLowerCase().includes('fetch')
      ) {
        setError(
          'Unable to connect to the SentinelForge backend. Please check the backend connection and try again.'
        )
      } else {
        setError(
          err?.message ||
            'Unable to complete the security scan.'
        )
      }
    } finally {
      setScanning(false)
    }
  }

  // ============================================================
  // SEVERITY
  // ============================================================

  const getSeverity = (finding) => {
    const severity =
      finding?.extra?.severity ||
      finding?.extra?.metadata?.severity

    if (!severity) {
      return 'MEDIUM'
    }

    const normalizedSeverity = String(
      severity
    ).toUpperCase()

    if (normalizedSeverity === 'ERROR') {
      return 'HIGH'
    }

    if (normalizedSeverity === 'WARNING') {
      return 'MEDIUM'
    }

    if (normalizedSeverity === 'INFO') {
      return 'LOW'
    }

    if (normalizedSeverity === 'CRITICAL') {
      return 'CRITICAL'
    }

    if (
      ['HIGH', 'MEDIUM', 'LOW'].includes(
        normalizedSeverity
      )
    ) {
      return normalizedSeverity
    }

    return 'MEDIUM'
  }

  // ============================================================
  // VULNERABILITY NAME
  // ============================================================

  const getVulnerabilityName = (finding) => {
    const vulnerabilities =
      finding?.extra?.metadata?.vulnerability_class

    if (
      Array.isArray(vulnerabilities) &&
      vulnerabilities.length > 0
    ) {
      return vulnerabilities[0]
    }

    const checkId = finding?.check_id

    if (checkId) {
      if (
        checkId.toLowerCase().includes('sql')
      ) {
        return 'SQL Injection'
      }

      if (
        checkId.toLowerCase().includes('xss')
      ) {
        return 'Cross-Site Scripting'
      }

      if (
        checkId.toLowerCase().includes('command')
      ) {
        return 'Command Injection'
      }

      if (
        checkId.toLowerCase().includes('secret')
      ) {
        return 'Hardcoded Secret'
      }
    }

    return 'Security Vulnerability'
  }

  // ============================================================
  // FILE NAME
  // ============================================================

  const getFileName = (path) => {
    if (!path) {
      return 'Unknown file'
    }

    return String(path).split(/[\\/]/).pop()
  }

  // ============================================================
  // RISK CLASS
  // ============================================================

  const getRiskClass = (level) => {
    if (!level) {
      return 'medium'
    }

    return String(level).toLowerCase()
  }

  // ============================================================
  // CWE FORMATTER
  // ============================================================

  const getCwe = (assessment, finding) => {
    if (
      Array.isArray(assessment?.cwe) &&
      assessment.cwe.length > 0
    ) {
      return assessment.cwe.join(', ')
    }

    if (
      typeof assessment?.cwe === 'string' &&
      assessment.cwe.trim()
    ) {
      return assessment.cwe
    }

    const cwe =
      finding?.extra?.metadata?.cwe

    if (Array.isArray(cwe) && cwe.length > 0) {
      return cwe.join(', ')
    }

    if (typeof cwe === 'string') {
      return cwe
    }

    return 'Security'
  }

  // ============================================================
  // HIGH RISK COUNT
  // ============================================================

  const getHighRiskCount = () => {
    if (!findings) {
      return 0
    }

    if (
      typeof findings.overall_risk?.high ===
      'number'
    ) {
      return findings.overall_risk.high
    }

    return findings.findings.filter(
      (finding) =>
        getSeverity(finding) === 'HIGH'
    ).length
  }

  // ============================================================
  // FILE COUNT
  // ============================================================

  const getFilesAffected = () => {
    if (!findings?.findings) {
      return 0
    }

    return new Set(
      findings.findings.map(
        (finding) => finding.path
      )
    ).size
  }

  // ============================================================
  // RENDER
  // ============================================================

  return (
    <div className="app">

      {/* ======================================================
          SIDEBAR
          ====================================================== */}

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


      {/* ======================================================
          MAIN
          ====================================================== */}

      <main className="main">

        {/* ====================================================
            TOP BAR
            ==================================================== */}

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


        {/* ====================================================
            CONTENT
            ==================================================== */}

        <section className="content">

          {/* ==================================================
              HERO
              ================================================== */}

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


          {/* ==================================================
              UPLOAD
              ================================================== */}

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
                  ? `${(
                      file.size /
                      1024 /
                      1024
                    ).toFixed(2)} MB`
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


          {/* ==================================================
              ERROR
              ================================================== */}

          {error && (

            <div className="error-box">

              <span>!</span>

              <div>

                <strong>
                  Scan Error
                </strong>

                <p>
                  {error}
                </p>

              </div>

            </div>

          )}


          {/* ==================================================
              RESULTS
              ================================================== */}

          {findings && (

            <>

              {/* =================================================
                  PHASE 2 - OVERALL RISK ASSESSMENT
                  ================================================= */}

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
                      findings.overall_risk?.overall_level
                    )}`}
                  >
                    {findings.overall_risk
                      ?.overall_level ||
                      'SECURE'}
                  </div>

                </div>


                {/* RISK SCORE */}

                <div className="risk-score">

                  <div className="risk-score-number">

                    {findings.overall_risk
                      ?.overall_score ?? 0}

                  </div>

                  <div className="risk-score-label">
                    / 10 Risk Score
                  </div>

                </div>


                {/* RISK BREAKDOWN */}

                <div className="risk-breakdown">

                  <div>

                    <span>
                      Critical
                    </span>

                    <strong>
                      {findings.overall_risk
                        ?.critical ?? 0}
                    </strong>

                  </div>

                  <div>

                    <span>
                      High
                    </span>

                    <strong>
                      {findings.overall_risk
                        ?.high ?? 0}
                    </strong>

                  </div>

                  <div>

                    <span>
                      Medium
                    </span>

                    <strong>
                      {findings.overall_risk
                        ?.medium ?? 0}
                    </strong>

                  </div>

                  <div>

                    <span>
                      Low
                    </span>

                    <strong>
                      {findings.overall_risk
                        ?.low ?? 0}
                    </strong>

                  </div>

                </div>

              </div>


              {/* =================================================
                  STATISTICS
                  ================================================= */}

              <div className="stats">

                {/* TOTAL FINDINGS */}

                <div className="stat-card">

                  <div className="stat-icon">
                    ◉
                  </div>

                  <div>

                    <span>
                      Total Findings
                    </span>

                    <strong>
                      {findings.findings_count}
                    </strong>

                  </div>

                </div>


                {/* HIGH RISK */}

                <div className="stat-card danger">

                  <div className="stat-icon">
                    !
                  </div>

                  <div>

                    <span>
                      High Risk
                    </span>

                    <strong>
                      {getHighRiskCount()}
                    </strong>

                  </div>

                </div>


                {/* FILES AFFECTED */}

                <div className="stat-card">

                  <div className="stat-icon">
                    #
                  </div>

                  <div>

                    <span>
                      Files Affected
                    </span>

                    <strong>
                      {getFilesAffected()}
                    </strong>

                  </div>

                </div>


                {/* SCANNER */}

                <div className="stat-card">

                  <div className="stat-icon">
                    ✓
                  </div>

                  <div>

                    <span>
                      Scanner
                    </span>

                    <strong>
                      Semgrep
                    </strong>

                  </div>

                </div>

              </div>


              {/* =================================================
                  SECURITY FINDINGS
                  ================================================= */}

              <div className="findings-section">

                <div className="section-title">

                  <div>

                    <h3>
                      Security Findings
                    </h3>

                    <p>
                      Detected vulnerabilities in{' '}
                      <strong>
                        {findings.filename ||
                          'uploaded repository'}
                      </strong>
                    </p>

                  </div>

                  <span className="finding-count">
                    {findings.findings_count}{' '}
                    Findings
                  </span>

                </div>


                {/* =================================================
                    NO FINDINGS
                    ================================================= */}

                {findings.findings.length === 0 ? (

                  <div className="no-findings">

                    <div>
                      ✓
                    </div>

                    <h3>
                      No vulnerabilities detected
                    </h3>

                    <p>
                      Your code passed the current
                      security checks.
                    </p>

                  </div>

                ) : (

                  /* =================================================
                     FINDING LIST
                     ================================================= */

                  <div className="finding-list">

                    {findings.findings.map(
                      (finding, index) => {

                        const severity =
                          getSeverity(finding)

                        const name =
                          getVulnerabilityName(
                            finding
                          )

                        /*
                         * Match the risk assessment
                         * with the finding.
                         *
                         * Normally backend returns
                         * them in the same order.
                         */

                        const assessment =
                          findings.risk_assessments?.[
                            index
                          ]

                        return (

                          <div
                            className="finding-card"
                            key={
                              finding?.check_id
                                ? `${finding.check_id}-${index}`
                                : index
                            }
                          >

                            {/* ====================================
                                SEVERITY ICON
                                ==================================== */}

                            <div
                              className={`finding-severity ${severity.toLowerCase()}`}
                            >

                              {severity ===
                              'CRITICAL'
                                ? '!!'
                                : severity ===
                                  'HIGH'
                                ? '!'
                                : severity ===
                                  'MEDIUM'
                                ? '•'
                                : '✓'}

                            </div>


                            {/* ====================================
                                MAIN FINDING CONTENT
                                ==================================== */}

                            <div className="finding-main">

                              {/* HEADING */}

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


                              {/* MESSAGE */}

                              <p className="finding-message">

                                {finding.extra
                                  ?.message ||
                                  'Security vulnerability detected.'}

                              </p>


                              {/* ==================================
                                  PHASE 2 RISK DETAILS
                                  ================================== */}

                              {assessment && (

                                <div className="risk-details">

                                  {/* RISK SCORE */}

                                  <div className="risk-detail">

                                    <span>
                                      Risk Score
                                    </span>

                                    <strong>
                                      {assessment.risk_score ??
                                        0}
                                      /10
                                    </strong>

                                  </div>


                                  {/* EXPLOITABILITY */}

                                  <div className="risk-detail">

                                    <span>
                                      Exploitability
                                    </span>

                                    <strong>
                                      {assessment.exploitability ||
                                        'UNKNOWN'}
                                    </strong>

                                  </div>


                                  {/* IMPACT */}

                                  <div className="risk-detail-wide">

                                    <span>
                                      Impact
                                    </span>

                                    <p>
                                      {assessment.impact ||
                                        'Impact information unavailable.'}
                                    </p>

                                  </div>


                                  {/* RECOMMENDATION */}

                                  <div className="risk-detail-wide">

                                    <span>
                                      Recommendation
                                    </span>

                                    <p>
                                      {assessment.recommendation ||
                                        'Review and remediate this vulnerability.'}
                                    </p>

                                  </div>

                                </div>

                              )}


                              {/* ==================================
                                  FINDING META
                                  ================================== */}

                              <div className="finding-meta">

                                <span>
                                  📄{' '}
                                  {getFileName(
                                    finding.path
                                  )}
                                </span>

                                <span>
                                  Line{' '}
                                  {finding.start
                                    ?.line || '-'}
                                </span>

                                <span>
                                  {getCwe(
                                    assessment,
                                    finding
                                  )}
                                </span>

                              </div>

                            </div>


                            {/* ==================================
                                ARROW
                                ================================== */}

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