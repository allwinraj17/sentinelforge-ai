import { useState } from 'react'
import emailjs from '@emailjs/browser'
import './App.css'

const API_URL = 'https://sentinelforge-ai.onrender.com'

const EMAILJS_SERVICE_ID =
  import.meta.env.VITE_EMAILJS_SERVICE_ID

const EMAILJS_TEMPLATE_ID =
  import.meta.env.VITE_EMAILJS_TEMPLATE_ID

const EMAILJS_PUBLIC_KEY =
  import.meta.env.VITE_EMAILJS_PUBLIC_KEY

function App() {
  // ============================================================
  // SCAN STATES
  // ============================================================

  const [file, setFile] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [findings, setFindings] = useState(null)
  const [error, setError] = useState(null)

  // ============================================================
  // AUTO-FIX STATES
  // ============================================================

  const [fixLoading, setFixLoading] = useState({})
  const [fixResults, setFixResults] = useState({})
  const [fixErrors, setFixErrors] = useState({})

  // ============================================================
  // EMAIL STATES
  // ============================================================

  const [email, setEmail] = useState('')
  const [emailLoading, setEmailLoading] = useState(false)
  const [emailSuccess, setEmailSuccess] = useState(null)
  const [emailError, setEmailError] = useState(null)

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

    setFixLoading({})
    setFixResults({})
    setFixErrors({})

    setEmailSuccess(null)
    setEmailError(null)
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

    setFixLoading({})
    setFixResults({})
    setFixErrors({})

    setEmailSuccess(null)
    setEmailError(null)

    const formData = new FormData()
    formData.append('file', file)

    try {
      const response = await fetch(
        `${API_URL}/scan/upload`,
        {
          method: 'POST',
          body: formData,
        }
      )

      const text = await response.text()

      console.log('SCAN HTTP STATUS:', response.status)
      console.log('SCAN RAW RESPONSE:', text)

      let data = null

      try {
        data = JSON.parse(text)
      } catch {
        throw new Error(
          `Backend returned an invalid response (${response.status}).`
        )
      }

      console.log('SCAN RESPONSE:', data)

      if (!response.ok) {
        throw new Error(
          data?.detail ||
            data?.message ||
            data?.error ||
            `Security scan failed (${response.status}).`
        )
      }

      if (!data) {
        throw new Error(
          'The backend returned an empty response.'
        )
      }

      const normalizedFindings =
        Array.isArray(data.findings)
          ? data.findings
          : []

      const normalizedRiskAssessments =
        Array.isArray(data.risk_assessments)
          ? data.risk_assessments
          : []

      const normalizedOverallRisk =
        data.overall_risk || {
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

        risk_assessments:
          normalizedRiskAssessments,

        overall_risk:
          normalizedOverallRisk,
      })
    } catch (err) {
      console.error(
        'Scan request error:',
        err
      )

      const errorMessage =
        err?.message?.toLowerCase() || ''

      if (
        err instanceof TypeError ||
        errorMessage.includes('fetch') ||
        errorMessage.includes('failed to fetch') ||
        errorMessage.includes('network')
      ) {
        setError(
          'Unable to connect to the SentinelForge backend. Please check that the Render backend is running.'
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
  // EXTRACT FIXED CODE
  // ============================================================

  const extractFixedCode = (data) => {
    if (!data) {
      return ''
    }

    // ----------------------------------------------------------
    // Direct fields
    // ----------------------------------------------------------

    const directCode =
      data.fixed_code ||
      data.fixedCode ||
      data.fixed_source_code ||
      data.fixedSourceCode ||
      data.code

    if (
      typeof directCode === 'string' &&
      directCode.trim()
    ) {
      return cleanCode(directCode)
    }

    // ----------------------------------------------------------
    // Nested result
    // ----------------------------------------------------------

    if (
      data.result &&
      typeof data.result === 'object'
    ) {
      const nestedCode =
        data.result.fixed_code ||
        data.result.fixedCode ||
        data.result.fixed_source_code ||
        data.result.fixedSourceCode ||
        data.result.code

      if (
        typeof nestedCode === 'string' &&
        nestedCode.trim()
      ) {
        return cleanCode(nestedCode)
      }
    }

    // ----------------------------------------------------------
    // Nested data
    // ----------------------------------------------------------

    if (
      data.data &&
      typeof data.data === 'object'
    ) {
      const nestedCode =
        data.data.fixed_code ||
        data.data.fixedCode ||
        data.data.fixed_source_code ||
        data.data.fixedSourceCode ||
        data.data.code

      if (
        typeof nestedCode === 'string' &&
        nestedCode.trim()
      ) {
        return cleanCode(nestedCode)
      }
    }

    // ----------------------------------------------------------
    // AI text response
    // ----------------------------------------------------------

    const possibleText =
      data.response ||
      data.ai_response ||
      data.aiResponse ||
      data.content ||
      data.message ||
      data.result

    if (typeof possibleText === 'string') {
      const text = possibleText.trim()

      // FIXED_CODE:
      const fixedCodeMatch = text.match(
        /FIXED_CODE\s*:\s*([\s\S]*?)(?=\n\s*(?:EXPLANATION|CONFIDENCE|$))/i
      )

      if (fixedCodeMatch?.[1]) {
        const code = cleanCode(
          fixedCodeMatch[1]
        )

        if (
          code &&
          code !== 'NOT_AVAILABLE'
        ) {
          return code
        }
      }

      // ```language ... ```
      const markdownMatch = text.match(
        /```(?:python|javascript|typescript|java|cpp|c|csharp|php|go|rust|ruby|sql|html|css|jsx|tsx)?\s*([\s\S]*?)```/i
      )

      if (markdownMatch?.[1]) {
        const code = markdownMatch[1].trim()

        if (code) {
          return code
        }
      }
    }

    return ''
  }

  // ============================================================
  // CLEAN GENERATED CODE
  // ============================================================

  const cleanCode = (code) => {
    if (
      typeof code !== 'string'
    ) {
      return ''
    }

    let cleaned = code.trim()

    // Remove markdown code fences
    cleaned = cleaned.replace(
      /^```[a-zA-Z0-9_-]*\s*/i,
      ''
    )

    cleaned = cleaned.replace(
      /\s*```$/i,
      ''
    )

    // Remove FIXED_CODE marker if accidentally included
    cleaned = cleaned.replace(
      /^FIXED_CODE\s*:\s*/i,
      ''
    )

    return cleaned.trim()
  }

  // ============================================================
  // EXTRACT FILENAME
  // ============================================================

  const extractFilename = (
    data,
    finding
  ) => {
    let filename =
      data?.filename ||
      data?.file_name ||
      data?.fixed_filename ||
      data?.fixedFileName ||
      finding?.path ||
      'fixed_source_file.txt'

    filename = String(filename)

    filename = filename.split(/[\\/]/).pop()

    if (
      !filename ||
      filename === '.' ||
      filename === '..'
    ) {
      filename = 'fixed_source_file.txt'
    }

    return filename
  }

  // ============================================================
  // DOWNLOAD FIXED FILE
  // ============================================================

  const handleDownloadFixedFile = (
    fixResult
  ) => {
    if (!fixResult) {
      return
    }

    const fixedCode =
      fixResult.fixed_code ||
      fixResult.fixedCode ||
      fixResult.code ||
      ''

    if (
      typeof fixedCode !== 'string' ||
      !fixedCode.trim()
    ) {
      alert(
        'No fixed code was returned by the Auto-Fix Agent.'
      )
      return
    }

    let filename =
      fixResult.filename ||
      fixResult.file_name ||
      fixResult.fixed_filename ||
      'fixed_source_file.txt'

    filename = String(filename)

    filename = filename.split(/[\\/]/).pop()

    const blob = new Blob(
      [fixedCode],
      {
        type: 'text/plain;charset=utf-8',
      }
    )

    const downloadUrl =
      window.URL.createObjectURL(blob)

    const link =
      document.createElement('a')

    link.href = downloadUrl
    link.download = filename

    document.body.appendChild(link)

    link.click()

    document.body.removeChild(link)

    setTimeout(() => {
      window.URL.revokeObjectURL(
        downloadUrl
      )
    }, 1000)
  }

  // ============================================================
  // AUTO-FIX AGENT
  // ============================================================

  const handleAutoFix = async (
    finding,
    index
  ) => {
    if (!finding) {
      return
    }

    if (!file) {
      setFixErrors((previous) => ({
        ...previous,
        [index]:
          'Original ZIP file is no longer available. Please upload the ZIP again.',
      }))

      return
    }

    const sourceCode =
      finding.source_code ||
      finding.sourceCode ||
      ''

    if (
      typeof sourceCode !== 'string' ||
      !sourceCode.trim()
    ) {
      setFixErrors((previous) => ({
        ...previous,
        [index]:
          'Source code context is not available for this vulnerability.',
      }))

      return
    }

    setFixLoading((previous) => ({
      ...previous,
      [index]: true,
    }))

    setFixErrors((previous) => {
      const updated = {
        ...previous,
      }

      delete updated[index]

      return updated
    })

    setFixResults((previous) => {
      const updated = {
        ...previous,
      }

      delete updated[index]

      return updated
    })

    try {
      const formData = new FormData()

      formData.append(
        'vulnerability',
        JSON.stringify(finding)
      )

      formData.append(
        'source_code',
        sourceCode
      )

      formData.append(
        'file',
        file
      )

      console.log(
        'Sending Auto-Fix request...'
      )

      const response =
        await fetch(
          `${API_URL}/scan/auto-fix`,
          {
            method: 'POST',
            body: formData,
          }
        )

      // IMPORTANT:
      // Read raw response first.
      // This lets us see exactly what Render returned.
      const text =
        await response.text()

      console.log(
        'AUTO-FIX HTTP STATUS:',
        response.status
      )

      console.log(
        'AUTO-FIX RAW RESPONSE:',
        text
      )

      let data = null

      try {
        data = JSON.parse(text)
      } catch {
        throw new Error(
          `Auto-Fix backend returned an invalid response (${response.status}). Response: ${text.substring(0, 500)}`
        )
      }

      console.log(
        'AUTO-FIX JSON RESPONSE:',
        data
      )

      // --------------------------------------------------------
      // HTTP ERROR
      // --------------------------------------------------------

      if (!response.ok) {
        throw new Error(
          data?.detail ||
            data?.message ||
            data?.error ||
            `Auto-Fix failed (${response.status}).`
        )
      }

      if (!data) {
        throw new Error(
          'Auto-Fix returned an empty response.'
        )
      }

      // --------------------------------------------------------
      // EXTRACT FIXED CODE
      // --------------------------------------------------------

      const fixedCode =
        extractFixedCode(data)

      console.log(
        'EXTRACTED FIXED CODE:',
        fixedCode
      )

      // --------------------------------------------------------
      // BACKEND EXPLICIT FAILURE
      // --------------------------------------------------------

      if (
        data.success === false &&
        !fixedCode
      ) {
        throw new Error(
          data.detail ||
            data.message ||
            data.error ||
            data.reason ||
            'Auto-Fix Agent failed to generate a fix.'
        )
      }

      // --------------------------------------------------------
      // NO FIXED CODE
      // --------------------------------------------------------

      if (!fixedCode) {
        throw new Error(
          'Auto-Fix returned HTTP 200, but no fixed code was found in the backend response.'
        )
      }

      // --------------------------------------------------------
      // NORMALIZE RESULT
      // --------------------------------------------------------

      const normalizedResult = {
        ...data,

        success: true,

        fixed_code:
          fixedCode,

        filename:
          extractFilename(
            data,
            finding
          ),
      }

      console.log(
        'NORMALIZED AUTO-FIX RESULT:',
        normalizedResult
      )

      setFixResults((previous) => ({
        ...previous,

        [index]:
          normalizedResult,
      }))
    } catch (err) {
      console.error(
        'Auto-Fix request error:',
        err
      )

      setFixErrors((previous) => ({
        ...previous,

        [index]:
          err?.message ||
          'Unable to generate the security fix.',
      }))
    } finally {
      setFixLoading((previous) => ({
        ...previous,
        [index]: false,
      }))
    }
  }

  // ============================================================
  // SEND SECURITY REPORT BY EMAIL
  // ============================================================

  const handleSendEmail = async () => {
    if (!findings) {
      setEmailError(
        'Please complete a security scan first.'
      )

      return
    }

    if (!email.trim()) {
      setEmailError(
        'Please enter your email address.'
      )

      return
    }

    const emailPattern =
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/

    if (
      !emailPattern.test(
        email.trim()
      )
    ) {
      setEmailError(
        'Please enter a valid email address.'
      )

      return
    }

    if (
      !EMAILJS_SERVICE_ID ||
      !EMAILJS_TEMPLATE_ID ||
      !EMAILJS_PUBLIC_KEY
    ) {
      setEmailError(
        'Email service is not configured. Please add the EmailJS environment variables in Vercel.'
      )

      return
    }

    setEmailLoading(true)
    setEmailSuccess(null)
    setEmailError(null)

    try {
      const overallRisk =
        findings.overall_risk || {}

      const totalFindings =
        findings.findings_count ??
        findings.findings?.length ??
        0

      const securityFindings =
        (findings.findings || [])
          .map(
            (
              finding,
              index
            ) => {
              const severity =
                getSeverity(
                  finding
                )

              const name =
                getVulnerabilityName(
                  finding
                )

              const assessment =
                findings
                  .risk_assessments?.[
                  index
                ]

              const fileName =
                getFileName(
                  finding.path
                )

              const line =
                finding.start?.line ||
                '-'

              const cwe =
                getCwe(
                  assessment,
                  finding
                )

              return `
Finding ${index + 1}

Vulnerability:
${name}

Severity:
${severity}

File:
${fileName}

Line:
${line}

CWE:
${cwe}

Message:
${
  finding.extra?.message ||
  'Security vulnerability detected.'
}

Risk Score:
${assessment?.risk_score ?? 0}/10

Exploitability:
${
  assessment?.exploitability ||
  'UNKNOWN'
}

Impact:
${
  assessment?.impact ||
  'Impact information unavailable.'
}

Recommendation:
${
  assessment?.recommendation ||
  'Review and remediate this vulnerability.'
}

--------------------------------
`
            }
          )
          .join('\n')

      const templateParams = {
        to_email:
          email.trim(),

        name:
          'SentinelForge AI',

        filename:
          findings.filename ||
          file?.name ||
          'security-report.zip',

        overall_risk:
          overallRisk.overall_level ||
          'SECURE',

        risk_score:
          overallRisk.overall_score ??
          0,

        total_findings:
          totalFindings,

        critical:
          overallRisk.critical ??
          0,

        high:
          overallRisk.high ??
          0,

        medium:
          overallRisk.medium ??
          0,

        low:
          overallRisk.low ??
          0,

        report:
          securityFindings ||
          'No security findings detected.',

        time:
          new Date().toLocaleString(),
      }

      console.log(
        'EmailJS template parameters:',
        templateParams
      )

      const response =
        await emailjs.send(
          EMAILJS_SERVICE_ID,
          EMAILJS_TEMPLATE_ID,
          templateParams,
          EMAILJS_PUBLIC_KEY
        )

      console.log(
        'EmailJS response:',
        response
      )

      if (
        response.status !== 200
      ) {
        throw new Error(
          'Email service returned an unexpected response.'
        )
      }

      setEmailSuccess(
        `Security report sent successfully to ${email.trim()}`
      )

      setEmail('')
    } catch (err) {
      console.error(
        'Email report error:',
        err
      )

      setEmailError(
        err?.text ||
        err?.message ||
        'Unable to send the security report.'
      )
    } finally {
      setEmailLoading(false)
    }
  }

  // ============================================================
  // SEVERITY
  // ============================================================

  const getSeverity = (
    finding
  ) => {
    const severity =
      finding?.extra?.severity ||
      finding?.extra?.metadata?.severity

    if (!severity) {
      return 'MEDIUM'
    }

    const normalizedSeverity =
      String(
        severity
      ).toUpperCase()

    if (
      normalizedSeverity ===
      'ERROR'
    ) {
      return 'HIGH'
    }

    if (
      normalizedSeverity ===
      'WARNING'
    ) {
      return 'MEDIUM'
    }

    if (
      normalizedSeverity ===
      'INFO'
    ) {
      return 'LOW'
    }

    if (
      normalizedSeverity ===
      'CRITICAL'
    ) {
      return 'CRITICAL'
    }

    if (
      [
        'HIGH',
        'MEDIUM',
        'LOW',
      ].includes(
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

  const getVulnerabilityName = (
    finding
  ) => {
    const vulnerabilities =
      finding?.extra?.metadata
        ?.vulnerability_class

    if (
      Array.isArray(
        vulnerabilities
      ) &&
      vulnerabilities.length > 0
    ) {
      return vulnerabilities[0]
    }

    const checkId =
      finding?.check_id

    if (checkId) {
      const lowerCheckId =
        checkId.toLowerCase()

      if (
        lowerCheckId.includes(
          'sql'
        )
      ) {
        return 'SQL Injection'
      }

      if (
        lowerCheckId.includes(
          'xss'
        )
      ) {
        return 'Cross-Site Scripting'
      }

      if (
        lowerCheckId.includes(
          'command'
        )
      ) {
        return 'Command Injection'
      }

      if (
        lowerCheckId.includes(
          'secret'
        )
      ) {
        return 'Hardcoded Secret'
      }
    }

    return 'Security Vulnerability'
  }

  // ============================================================
  // FILE NAME
  // ============================================================

  const getFileName = (
    path
  ) => {
    if (!path) {
      return 'Unknown file'
    }

    return String(path)
      .split(/[\\/]/)
      .pop()
  }

  // ============================================================
  // RISK CLASS
  // ============================================================

  const getRiskClass = (
    level
  ) => {
    if (!level) {
      return 'medium'
    }

    return String(level)
      .toLowerCase()
  }

  // ============================================================
  // CWE
  // ============================================================

  const getCwe = (
    assessment,
    finding
  ) => {
    if (
      Array.isArray(
        assessment?.cwe
      ) &&
      assessment.cwe.length > 0
    ) {
      return assessment.cwe.join(
        ', '
      )
    }

    if (
      typeof assessment?.cwe ===
        'string' &&
      assessment.cwe.trim()
    ) {
      return assessment.cwe
    }

    const cwe =
      finding?.extra?.metadata?.cwe

    if (
      Array.isArray(cwe) &&
      cwe.length > 0
    ) {
      return cwe.join(
        ', '
      )
    }

    if (
      typeof cwe === 'string'
    ) {
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
      typeof findings
        .overall_risk
        ?.high === 'number'
    ) {
      return findings
        .overall_risk
        .high
    }

    return (
      findings.findings || []
    ).filter(
      (finding) =>
        getSeverity(
          finding
        ) === 'HIGH'
    ).length
  }

  // ============================================================
  // FILE COUNT
  // ============================================================

  const getFilesAffected = () => {
    if (
      !findings?.findings
    ) {
      return 0
    }

    return new Set(
      findings.findings.map(
        (finding) =>
          finding.path
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

            <h1>
              SentinelForge
            </h1>

            <span>
              AI Security Platform
            </span>

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

              <strong>
                Backend Online
              </strong>

              <small>
                FastAPI connected
              </small>

            </div>

          </div>

        </div>

      </aside>

      {/* ======================================================
          MAIN
      ====================================================== */}

      <main className="main">

        {/* TOP BAR */}

        <header className="topbar">

          <div>

            <span className="breadcrumb">
              Dashboard / Security Scanner
            </span>

            <h2>
              Code Security
            </h2>

          </div>

          <div className="online">

            <span></span>

            Cloud Backend

          </div>

        </header>

        {/* CONTENT */}

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
                Upload a ZIP file and
                SentinelForge will scan your
                source code for security
                vulnerabilities and generate
                AI-powered security fixes.
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

                <h3>
                  Scan Code
                </h3>

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
                onChange={
                  handleFileChange
                }
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
              onClick={
                handleScan
              }
              disabled={
                !file ||
                scanning
              }
            >

              {scanning ? (
                <>
                  <span className="spinner"></span>
                  Scanning Code...
                </>
              ) : (
                <>
                  Start Security Scan
                  <span>
                    →
                  </span>
                </>
              )}

            </button>

          </div>

          {/* ==================================================
              ERROR
          ================================================== */}

          {error && (

            <div className="error-box">

              <span>
                !
              </span>

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
                  PHASE 2
              ================================================= */}

              <div className="risk-overview">

                <div className="risk-overview-header">

                  <div>

                    <span className="hero-label">
                      PHASE 2
                    </span>

                    <h3>
                      Overall Security Risk
                    </h3>

                  </div>

                  <div
                    className={`overall-risk-badge ${getRiskClass(
                      findings
                        .overall_risk
                        ?.overall_level
                    )}`}
                  >

                    {findings
                      .overall_risk
                      ?.overall_level ||
                      'SECURE'}

                  </div>

                </div>

                <div className="risk-score">

                  <div className="risk-score-number">

                    {findings
                      .overall_risk
                      ?.overall_score ?? 0}

                  </div>

                  <div className="risk-score-label">
                    / 10 Risk Score
                  </div>

                </div>

                <div className="risk-breakdown">

                  <div>
                    <span>Critical</span>
                    <strong>
                      {findings
                        .overall_risk
                        ?.critical ?? 0}
                    </strong>
                  </div>

                  <div>
                    <span>High</span>
                    <strong>
                      {findings
                        .overall_risk
                        ?.high ?? 0}
                    </strong>
                  </div>

                  <div>
                    <span>Medium</span>
                    <strong>
                      {findings
                        .overall_risk
                        ?.medium ?? 0}
                    </strong>
                  </div>

                  <div>
                    <span>Low</span>
                    <strong>
                      {findings
                        .overall_risk
                        ?.low ?? 0}
                    </strong>
                  </div>

                </div>

              </div>

              {/* =================================================
                  PHASE 3
              ================================================= */}

              <div className="risk-overview">

                <div className="risk-overview-header">

                  <div>

                    <span className="hero-label">
                      PHASE 3
                    </span>

                    <h3>
                      AI Auto-Fix Agent
                    </h3>

                    <p>
                      Generate secure code-fix
                      suggestions using the detected
                      vulnerability and source-code context.
                    </p>

                  </div>

                  <div className="overall-risk-badge">
                    AI POWERED
                  </div>

                </div>

              </div>

              {/* =================================================
                  EMAIL REPORT
              ================================================= */}

              <div className="upload-card email-report-card">

                <div className="section-title">

                  <div>

                    <span className="hero-label">
                      REPORT DELIVERY
                    </span>

                    <h3>
                      Email Security Report
                    </h3>

                    <p>
                      Enter your email address to receive
                      the complete security analysis report.
                    </p>

                  </div>

                  <span className="supported">
                    EMAILJS
                  </span>

                </div>

                <div
                  style={{
                    display: 'flex',
                    gap: '12px',
                    marginTop: '20px',
                    flexWrap: 'wrap',
                  }}
                >

                  <input
                    type="email"
                    placeholder="Enter your email address"
                    value={email}
                    onChange={(e) => {
                      setEmail(
                        e.target.value
                      )

                      setEmailSuccess(null)
                      setEmailError(null)
                    }}
                    disabled={
                      emailLoading
                    }
                    style={{
                      flex: '1',
                      minWidth: '240px',
                      padding: '14px 16px',
                      border:
                        '1px solid #d1d5db',
                      borderRadius: '8px',
                      fontSize: '15px',
                      outline: 'none',
                    }}
                  />

                  <button
                    className="scan-button"
                    onClick={
                      handleSendEmail
                    }
                    disabled={
                      emailLoading
                    }
                    style={{
                      marginTop: 0,
                      minWidth: '190px',
                    }}
                  >

                    {emailLoading ? (
                      <>
                        <span className="spinner"></span>
                        Sending Report...
                      </>
                    ) : (
                      <>
                        ✉ Send Report
                        <span>
                          →
                        </span>
                      </>
                    )}

                  </button>

                </div>

                {emailSuccess && (

                  <div
                    className="auto-fix-result"
                    style={{
                      marginTop: '18px',
                    }}
                  >

                    <strong>
                      ✓ Report Sent Successfully
                    </strong>

                    <p>
                      {emailSuccess}
                    </p>

                  </div>

                )}

                {emailError && (

                  <div
                    className="auto-fix-error"
                    style={{
                      marginTop: '18px',
                    }}
                  >

                    <strong>
                      Email Error
                    </strong>

                    <p>
                      {emailError}
                    </p>

                  </div>

                )}

              </div>

              {/* =================================================
                  STATISTICS
              ================================================= */}

              <div className="stats">

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

                    {findings.findings_count}
                    {' '}
                    Findings

                  </span>

                </div>

                {/* NO FINDINGS */}

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

                  <div className="finding-list">

                    {findings.findings.map(
                      (
                        finding,
                        index
                      ) => {

                        const severity =
                          getSeverity(
                            finding
                          )

                        const name =
                          getVulnerabilityName(
                            finding
                          )

                        const assessment =
                          findings
                            .risk_assessments?.[
                            index
                          ]

                        const fixResult =
                          fixResults[index]

                        const fixError =
                          fixErrors[index]

                        const isFixing =
                          fixLoading[index]

                        return (

                          <div
                            className="finding-card"
                            key={
                              finding?.check_id
                                ? `${finding.check_id}-${index}`
                                : index
                            }
                          >

                            {/* SEVERITY ICON */}

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

                            {/* MAIN FINDING */}

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

                                {finding.extra
                                  ?.message ||
                                  'Security vulnerability detected.'}

                              </p>

                              {/* RISK DETAILS */}

                              {assessment && (

                                <div className="risk-details">

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

                                  <div className="risk-detail">

                                    <span>
                                      Exploitability
                                    </span>

                                    <strong>
                                      {assessment.exploitability ||
                                        'UNKNOWN'}
                                    </strong>

                                  </div>

                                  <div className="risk-detail-wide">

                                    <span>
                                      Impact
                                    </span>

                                    <p>
                                      {assessment.impact ||
                                        'Impact information unavailable.'}
                                    </p>

                                  </div>

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

                              {/* FINDING META */}

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
                                  {getCwe(
                                    assessment,
                                    finding
                                  )}
                                </span>

                              </div>

                              {/* =================================================
                                  AUTO FIX
                              ================================================= */}

                              <div className="auto-fix-section">

                                <button
                                  className="auto-fix-button"
                                  onClick={() =>
                                    handleAutoFix(
                                      finding,
                                      index
                                    )
                                  }
                                  disabled={
                                    isFixing
                                  }
                                >

                                  {isFixing ? (
                                    <>
                                      <span className="spinner"></span>
                                      Generating Fix...
                                    </>
                                  ) : (
                                    <>
                                      🛠 Generate Auto-Fix
                                      <span>
                                        →
                                      </span>
                                    </>
                                  )}

                                </button>

                                <small>
                                  AI will generate a secure
                                  fixed copy of this vulnerable
                                  file. Your original repository
                                  will not be modified.
                                </small>

                              </div>

                              {/* AUTO FIX ERROR */}

                              {fixError && (

                                <div className="auto-fix-error">

                                  <strong>
                                    Auto-Fix Error
                                  </strong>

                                  <p>
                                    {fixError}
                                  </p>

                                </div>

                              )}

                              {/* =================================================
                                  AUTO FIX RESULT
                              ================================================= */}

                              {fixResult && (

                                <div className="auto-fix-result">

                                  <div className="auto-fix-result-header">

                                    <div>

                                      <span className="hero-label">
                                        PHASE 3 RESULT
                                      </span>

                                      <h3>
                                        AI-Fixed Security File
                                      </h3>

                                    </div>

                                    <span className="auto-fix-status">
                                      FIX GENERATED
                                    </span>

                                  </div>

                                  {/* FILE INFORMATION */}

                                  <div
                                    style={{
                                      marginTop: '12px',
                                      marginBottom: '12px',
                                    }}
                                  >

                                    <strong>
                                      Fixed File:
                                    </strong>

                                    <span
                                      style={{
                                        marginLeft: '8px',
                                      }}
                                    >
                                      {fixResult.filename ||
                                        'fixed_source_file.txt'}
                                    </span>

                                  </div>

                                  {/* FIXED CODE */}

                                  <div className="fix-content">

                                    <pre>
                                      {fixResult.fixed_code ||
                                        'No fixed code was returned.'}
                                    </pre>

                                  </div>

                                  {/* DOWNLOAD BUTTON */}

                                  <button
                                    type="button"
                                    className="auto-fix-button"
                                    onClick={() =>
                                      handleDownloadFixedFile(
                                        fixResult
                                      )
                                    }
                                    style={{
                                      marginTop: '16px',
                                    }}
                                  >

                                    ⬇ Download Fixed File

                                    <span>
                                      →
                                    </span>

                                  </button>

                                  {/* DISCLAIMER */}

                                  <p
                                    className="fix-disclaimer"
                                    style={{
                                      marginTop: '12px',
                                    }}
                                  >

                                    ✓ SentinelForge created a
                                    new fixed copy of the
                                    vulnerable file.

                                    <br />

                                    ✓ The original uploaded ZIP
                                    was not modified.

                                    <br />

                                    ⚠ Review and test the
                                    generated file before using
                                    it in production.

                                  </p>

                                </div>

                              )}

                            </div>

                            {/* ARROW */}

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