import { useMemo, useState } from "react";
import emailjs from "@emailjs/browser";
import { jsPDF } from "jspdf";
import JSZip from "jszip";
import "./App.css";


// ============================================================
// CONFIGURATION
// ============================================================

const API_URL =
  import.meta.env.VITE_API_URL ||
  "https://sentinelforge-ai.onrender.com";

const EMAILJS_SERVICE_ID =
  import.meta.env.VITE_EMAILJS_SERVICE_ID || "";

const EMAILJS_TEMPLATE_ID =
  import.meta.env.VITE_EMAILJS_TEMPLATE_ID || "";

const EMAILJS_PUBLIC_KEY =
  import.meta.env.VITE_EMAILJS_PUBLIC_KEY || "";


// ============================================================
// DEFAULT PIPELINE
// ============================================================

const DEFAULT_STAGES = [
  {
    id: "repository",
    title: "Repository Received",
    status: "pending",
    message: "",
  },
  {
    id: "extract",
    title: "Repository Extraction",
    status: "pending",
    message: "",
  },
  {
    id: "semgrep",
    title: "Security Detection",
    status: "pending",
    message: "",
  },
  {
    id: "risk",
    title: "Risk Assessment",
    status: "pending",
    message: "",
  },
  {
    id: "ai",
    title: "AI Security Analysis",
    status: "pending",
    message: "",
  },
  {
    id: "fix",
    title: "AI Auto-Fix",
    status: "pending",
    message: "",
  },
  {
    id: "validation",
    title: "Validation Preparation",
    status: "pending",
    message: "",
  },
];


// ============================================================
// HELPERS
// ============================================================

function normalizePath(path = "") {
  return String(path)
    .replaceAll("\\", "/")
    .replace(/^\.\/+/, "")
    .replace(/^\/+/, "");
}


function getSeverity(finding, assessment) {
  return (
    assessment?.severity ||
    finding?.extra?.severity ||
    "UNKNOWN"
  );
}


function getVulnerabilityType(finding, assessment) {
  return (
    assessment?.vulnerability_type ||
    finding?.extra?.metadata?.vulnerability_class ||
    "Security Vulnerability"
  );
}


function getLine(finding) {
  return (
    finding?.start?.line ||
    finding?.line ||
    "Unknown"
  );
}


function getMessage(finding) {
  return (
    finding?.extra?.message ||
    "Security issue detected."
  );
}


function getCwe(finding, assessment) {
  const cwe =
    assessment?.cwe ||
    finding?.extra?.metadata?.cwe ||
    "";

  if (Array.isArray(cwe)) {
    return cwe.join(", ");
  }

  return cwe || "Not specified";
}


function getRiskScore(assessment) {
  return (
    assessment?.risk_score ??
    assessment?.score ??
    "N/A"
  );
}


function getRiskLevel(assessment) {
  return (
    assessment?.risk_level ||
    assessment?.level ||
    "N/A"
  );
}


function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);

  const link = document.createElement("a");

  link.href = url;
  link.download = filename;

  document.body.appendChild(link);

  link.click();

  link.remove();

  setTimeout(() => {
    URL.revokeObjectURL(url);
  }, 1000);
}


function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}


// ============================================================
// APP
// ============================================================

export default function App() {
  // ----------------------------------------------------------
  // INPUT
  // ----------------------------------------------------------

  const [role, setRole] = useState("student");
  const [email, setEmail] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);

  // ----------------------------------------------------------
  // STATE
  // ----------------------------------------------------------

  const [running, setRunning] = useState(false);
  const [completed, setCompleted] = useState(false);

  const [error, setError] = useState("");

  const [scanData, setScanData] = useState(null);

  const [stages, setStages] = useState(
    DEFAULT_STAGES
  );

  const [emailStatus, setEmailStatus] =
    useState("");

  const [reportStatus, setReportStatus] =
    useState("");

  const [zipStatus, setZipStatus] =
    useState("");

  const [pdfDownloaded, setPdfDownloaded] =
    useState(false);

  const [zipDownloaded, setZipDownloaded] =
    useState(false);


  // ----------------------------------------------------------
  // DERIVED DATA
  // ----------------------------------------------------------

  const findings = scanData?.findings || [];

  const riskAssessments =
    scanData?.risk_assessments || [];

  const overallRisk =
    scanData?.overall_risk || {};

  const aiAnalysis =
    scanData?.ai_analysis || "";

  const fixes =
    scanData?.fixes || [];


  const successfulFixCount = useMemo(() => {
    return fixes.filter(
      (item) => item?.success
    ).length;
  }, [fixes]);


  const failedFixCount = useMemo(() => {
    return fixes.filter(
      (item) => !item?.success
    ).length;
  }, [fixes]);


  const severityCounts = useMemo(() => {
    const counts = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };

    findings.forEach((finding, index) => {
      const assessment =
        riskAssessments[index] || {};

      const severity = String(
        getSeverity(
          finding,
          assessment
        )
      ).toUpperCase();

      if (
        Object.prototype.hasOwnProperty.call(
          counts,
          severity
        )
      ) {
        counts[severity] += 1;
      }
    });

    return counts;
  }, [
    findings,
    riskAssessments,
  ]);


  // ==========================================================
  // FILE SELECT
  // ==========================================================

  function handleFileChange(event) {
    const file =
      event.target.files?.[0] || null;

    setSelectedFile(file);

    setError("");
    setCompleted(false);

    setScanData(null);

    setStages(DEFAULT_STAGES);

    setEmailStatus("");
    setReportStatus("");
    setZipStatus("");

    setPdfDownloaded(false);
    setZipDownloaded(false);
  }


  // ==========================================================
  // START AUTONOMOUS ANALYSIS
  // ==========================================================

  async function startAutonomousAnalysis() {
    setError("");

    setCompleted(false);

    setScanData(null);

    setEmailStatus("");
    setReportStatus("");
    setZipStatus("");

    setPdfDownloaded(false);
    setZipDownloaded(false);

    // --------------------------------------------------------
    // VALIDATE INPUT
    // --------------------------------------------------------

    if (!role) {
      setError(
        "Please select your role."
      );
      return;
    }

    if (!email.trim()) {
      setError(
        "Please enter your email address."
      );
      return;
    }

    if (!email.includes("@")) {
      setError(
        "Please enter a valid email address."
      );
      return;
    }

    if (!selectedFile) {
      setError(
        "Please upload a repository ZIP file."
      );
      return;
    }

    if (
      !selectedFile.name
        .toLowerCase()
        .endsWith(".zip")
    ) {
      setError(
        "Only ZIP repository files are supported."
      );
      return;
    }

    // --------------------------------------------------------
    // START
    // --------------------------------------------------------

    setRunning(true);

    setStages(
      DEFAULT_STAGES.map((stage, index) => {
        if (index === 0) {
          return {
            ...stage,
            status: "running",
            message:
              "Preparing repository submission...",
          };
        }

        return {
          ...stage,
          status: "pending",
          message: "",
        };
      })
    );

    try {
      // ------------------------------------------------------
      // BUILD FORM DATA
      // ------------------------------------------------------

      const formData = new FormData();

      formData.append(
        "role",
        role
      );

      formData.append(
        "email",
        email.trim()
      );

      formData.append(
        "file",
        selectedFile
      );

      // ------------------------------------------------------
      // SEND TO MASTER ENDPOINT
      // ------------------------------------------------------

      const response = await fetch(
        `${API_URL}/scan/start`,
        {
          method: "POST",
          body: formData,
        }
      );

      let data = null;

      try {
        data = await response.json();
      } catch {
        throw new Error(
          `Backend returned an invalid response (${response.status}).`
        );
      }

      if (!response.ok) {
        throw new Error(
          data?.detail ||
            "Autonomous security analysis failed."
        );
      }

      if (!data?.success) {
        throw new Error(
          data?.message ||
            "Autonomous analysis did not complete successfully."
        );
      }

      // ------------------------------------------------------
      // STORE RESULTS
      // ------------------------------------------------------

      setScanData(data);

      // ------------------------------------------------------
      // USE BACKEND PIPELINE STATUS
      // ------------------------------------------------------

      if (
        Array.isArray(data.stages) &&
        data.stages.length > 0
      ) {
        setStages(data.stages);
      } else {
        setStages(
          DEFAULT_STAGES.map(
            (stage) => ({
              ...stage,
              status: "completed",
            })
          )
        );
      }

      setCompleted(true);

      // ------------------------------------------------------
      // AUTO ACTIONS
      // ------------------------------------------------------

      // Generate and download PDF.
      try {
        await generatePDFReport(
          data
        );

        setPdfDownloaded(true);
        setReportStatus(
          "Security report PDF generated and downloaded."
        );
      } catch (pdfError) {
        console.error(
          "PDF generation error:",
          pdfError
        );

        setReportStatus(
          `PDF generation failed: ${pdfError.message}`
        );
      }

      // Generate and download fixed repository ZIP.
      try {
        await generateFixedRepositoryZip(
          selectedFile,
          data
        );
      } catch (zipError) {
        console.error(
          "Fixed ZIP error:",
          zipError
        );

        setZipStatus(
          `Fixed repository ZIP failed: ${zipError.message}`
        );
      }

      // Send email.
      try {
        await sendEmailReport(
          data
        );
      } catch (emailError) {
        console.error(
          "Email error:",
          emailError
        );

        setEmailStatus(
          `Email delivery failed: ${emailError.message}`
        );
      }

    } catch (requestError) {
      console.error(
        "Autonomous analysis error:",
        requestError
      );

      setError(
        requestError.message ||
          "Something went wrong."
      );

      setStages(
        DEFAULT_STAGES.map(
          (stage) => ({
            ...stage,
            status: "pending",
          })
        )
      );

    } finally {
      setRunning(false);
    }
  }


  // ==========================================================
  // PDF GENERATION
  // ==========================================================

  async function generatePDFReport(data) {
    const reportRole =
      data?.role || role;

    const reportFindings =
      data?.findings || [];

    const reportAssessments =
      data?.risk_assessments || [];

    const reportRisk =
      data?.overall_risk || {};

    const reportAI =
      data?.ai_analysis || "";

    const reportFixes =
      data?.fixes || [];

    const repositoryName =
      data?.filename ||
      selectedFile?.name ||
      "repository.zip";


    const doc = new jsPDF({
      unit: "mm",
      format: "a4",
    });


    let y = 18;

    const pageWidth =
      doc.internal.pageSize.getWidth();

    const pageHeight =
      doc.internal.pageSize.getHeight();


    function addPageIfNeeded(
      requiredHeight = 12
    ) {
      if (
        y + requiredHeight >
        pageHeight - 16
      ) {
        doc.addPage();
        y = 18;
      }
    }


    function writeText(
      text,
      options = {}
    ) {
      const fontSize =
        options.fontSize || 10;

      const bold =
        options.bold || false;

      const maxWidth =
        options.maxWidth ||
        pageWidth - 30;

      const lineHeight =
        options.lineHeight ||
        5;

      doc.setFontSize(
        fontSize
      );

      doc.setFont(
        "helvetica",
        bold ? "bold" : "normal"
      );

      const lines =
        doc.splitTextToSize(
          String(text ?? ""),
          maxWidth
        );

      addPageIfNeeded(
        lines.length *
          lineHeight +
          2
      );

      doc.text(
        lines,
        15,
        y
      );

      y +=
        lines.length *
        lineHeight;

      return lines;
    }


    // --------------------------------------------------------
    // HEADER
    // --------------------------------------------------------

    doc.setFontSize(22);

    doc.setFont(
      "helvetica",
      "bold"
    );

    doc.text(
      "SentinelForge AI",
      15,
      y
    );

    y += 8;

    doc.setFontSize(12);

    doc.setFont(
      "helvetica",
      "normal"
    );

    doc.text(
      "Autonomous Repository Security Analysis Report",
      15,
      y
    );

    y += 10;

    doc.line(
      15,
      y,
      pageWidth - 15,
      y
    );

    y += 10;


    // --------------------------------------------------------
    // REPORT INFORMATION
    // --------------------------------------------------------

    writeText(
      `Repository: ${repositoryName}`,
      {
        bold: true,
        fontSize: 11,
      }
    );

    writeText(
      `Role: ${
        reportRole === "student"
          ? "Student"
          : "Developer"
      }`
    );

    writeText(
      `Email: ${data?.email || email}`
    );

    writeText(
      `Vulnerabilities Detected: ${
        reportFindings.length
      }`
    );

    writeText(
      `Overall Risk Score: ${
        reportRisk.score ??
        reportRisk.overall_score ??
        "N/A"
      }`
    );

    writeText(
      `Overall Risk Level: ${
        reportRisk.risk_level ??
        reportRisk.level ??
        "N/A"
      }`
    );

    y += 5;


    // --------------------------------------------------------
    // STUDENT REPORT
    // --------------------------------------------------------

    if (
      reportRole === "student"
    ) {
      writeText(
        "Security Learning Summary",
        {
          fontSize: 15,
          bold: true,
        }
      );

      writeText(
        "This section explains the security issues in a simple and educational manner."
      );

      y += 4;

      if (
        reportFindings.length === 0
      ) {
        writeText(
          "No security vulnerabilities were detected during the automated security scan."
        );
      }


      reportFindings.forEach(
        (finding, index) => {
          const assessment =
            reportAssessments[
              index
            ] || {};

          const vulnerability =
            getVulnerabilityType(
              finding,
              assessment
            );

          const path =
            finding?.path ||
            "Unknown";

          const line =
            getLine(finding);

          const message =
            getMessage(finding);

          const impact =
            assessment?.impact ||
            "Potential impact depends on how the vulnerable functionality is used.";

          const exploitability =
            assessment?.exploitability ||
            "An attacker may be able to abuse the vulnerable code depending on application exposure and input control.";

          const recommendation =
            assessment?.recommendation ||
            "Apply secure coding practices and validate untrusted input.";

          writeText(
            `Vulnerability ${index + 1}: ${vulnerability}`,
            {
              fontSize: 13,
              bold: true,
            }
          );

          writeText(
            `Where: ${path} at line ${line}`
          );

          writeText(
            `What was detected: ${message}`
          );

          writeText(
            `Possible attack path: ${exploitability}`
          );

          writeText(
            `Impact if not fixed: ${impact}`
          );

          writeText(
            `Prevention / Fix: ${recommendation}`
          );

          writeText(
            "What SentinelForge AI did: The repository was scanned, the risk was assessed, and an AI-generated remediation copy was prepared when sufficient source context was available."
          );

          y += 5;
        }
      );
    }


    // --------------------------------------------------------
    // DEVELOPER REPORT
    // --------------------------------------------------------

    else {
      writeText(
        "Technical Security Findings",
        {
          fontSize: 15,
          bold: true,
        }
      );

      y += 4;

      if (
        reportFindings.length === 0
      ) {
        writeText(
          "No security vulnerabilities were detected during the automated security scan."
        );
      }


      reportFindings.forEach(
        (finding, index) => {
          const assessment =
            reportAssessments[
              index
            ] || {};

          const vulnerability =
            getVulnerabilityType(
              finding,
              assessment
            );

          const checkId =
            finding?.check_id ||
            "Unknown";

          const path =
            finding?.path ||
            "Unknown";

          const line =
            getLine(finding);

          const severity =
            getSeverity(
              finding,
              assessment
            );

          const cwe =
            getCwe(
              finding,
              assessment
            );

          const riskScore =
            getRiskScore(
              assessment
            );

          const riskLevel =
            getRiskLevel(
              assessment
            );

          const message =
            getMessage(finding);

          const impact =
            assessment?.impact ||
            "Not specified";

          const exploitability =
            assessment?.exploitability ||
            "Not specified";

          const recommendation =
            assessment?.recommendation ||
            "Not specified";


          writeText(
            `Finding ${index + 1}: ${vulnerability}`,
            {
              fontSize: 13,
              bold: true,
            }
          );

          writeText(
            `Semgrep Rule: ${checkId}`
          );

          writeText(
            `File: ${path}`
          );

          writeText(
            `Line: ${line}`
          );

          writeText(
            `Severity: ${severity}`
          );

          writeText(
            `CWE: ${cwe}`
          );

          writeText(
            `Risk Score: ${riskScore}`
          );

          writeText(
            `Risk Level: ${riskLevel}`
          );

          writeText(
            `Semgrep Message: ${message}`
          );

          writeText(
            `Impact: ${impact}`
          );

          writeText(
            `Exploitability: ${exploitability}`
          );

          writeText(
            `Recommended Remediation: ${recommendation}`
          );

          if (
            finding?.source_code
          ) {
            writeText(
              "Source Context:",
              {
                bold: true,
              }
            );

            writeText(
              finding.source_code,
              {
                fontSize: 8,
                lineHeight: 4,
              }
            );
          }

          y += 5;
        }
      );
    }


    // --------------------------------------------------------
    // AI ANALYSIS
    // --------------------------------------------------------

    writeText(
      "AI Security Analysis",
      {
        fontSize: 15,
        bold: true,
      }
    );

    if (reportAI) {
      writeText(
        reportAI,
        {
          fontSize: 9,
          lineHeight: 4.5,
        }
      );
    } else {
      writeText(
        "No AI analysis was returned."
      );
    }

    y += 4;


    // --------------------------------------------------------
    // AUTO-FIX
    // --------------------------------------------------------

    writeText(
      "AI Auto-Fix Summary",
      {
        fontSize: 15,
        bold: true,
      }
    );

    writeText(
      `Successful fixes generated: ${
        reportFixes.filter(
          (item) => item?.success
        ).length
      }`
    );

    writeText(
      `Fixes that could not be generated: ${
        reportFixes.filter(
          (item) => !item?.success
        ).length
      }`
    );

    writeText(
      "The original uploaded repository was not modified. SentinelForge AI generated corrected copies for findings where sufficient source context was available."
    );

    writeText(
      "Important: Phase 4 does not perform a second security scan after auto-fix generation. Therefore the generated fixes are not claimed as security-verified."
    );


    // --------------------------------------------------------
    // SEVERITY SUMMARY
    // --------------------------------------------------------

    writeText(
      "Severity Summary",
      {
        fontSize: 15,
        bold: true,
      }
    );

    writeText(
      `Critical: ${
        severityCounts.CRITICAL
      }`
    );

    writeText(
      `High: ${
        severityCounts.HIGH
      }`
    );

    writeText(
      `Medium: ${
        severityCounts.MEDIUM
      }`
    );

    writeText(
      `Low: ${
        severityCounts.LOW
      }`
    );

    writeText(
      `Info: ${
        severityCounts.INFO
      }`
    );


    // --------------------------------------------------------
    // FOOTER
    // --------------------------------------------------------

    addPageIfNeeded(10);

    y += 8;

    doc.line(
      15,
      y,
      pageWidth - 15,
      y
    );

    y += 7;

    writeText(
      "Generated by SentinelForge AI.",
      {
        fontSize: 8,
      }
    );

    writeText(
      "Autonomous analysis completed without a post-fix second security scan.",
      {
        fontSize: 8,
      }
    );


    // --------------------------------------------------------
    // DOWNLOAD
    // --------------------------------------------------------

    const safeName =
      String(repositoryName)
        .replace(/\.zip$/i, "")
        .replace(/[^\w.-]+/g, "_");

    doc.save(
      `SentinelForge_${safeName}_Security_Report.pdf`
    );
  }


  // ==========================================================
  // FIXED REPOSITORY ZIP
  // ==========================================================

  async function generateFixedRepositoryZip(
    originalFile,
    data
  ) {
    if (!originalFile) {
      throw new Error(
        "Original repository file is unavailable."
      );
    }

    const repositoryFixes =
      data?.fixes || [];

    setZipStatus(
      "Preparing fixed repository ZIP..."
    );

    // --------------------------------------------------------
    // LOAD ORIGINAL ZIP
    // --------------------------------------------------------

    const originalBuffer =
      await originalFile.arrayBuffer();

    const zip =
      await JSZip.loadAsync(
        originalBuffer
      );

    // --------------------------------------------------------
    // APPLY FIXED FILES
    // --------------------------------------------------------

    let replacedCount = 0;
    let skippedCount = 0;

    for (
      const fix of repositoryFixes
    ) {
      if (
        !fix?.success ||
        !fix?.fixed_code ||
        !fix?.original_path
      ) {
        skippedCount += 1;
        continue;
      }

      const targetPath =
        normalizePath(
          fix.original_path
        );

      if (!targetPath) {
        skippedCount += 1;
        continue;
      }

      const exactEntry =
        zip.file(targetPath);

      if (exactEntry) {
        zip.file(
          targetPath,
          fix.fixed_code
        );

        replacedCount += 1;
        continue;
      }

      // ------------------------------------------------------
      // TRY "./" VARIANT
      // ------------------------------------------------------

      const dotEntry =
        zip.file(
          `./${targetPath}`
        );

      if (dotEntry) {
        zip.file(
          `./${targetPath}`,
          fix.fixed_code
        );

        replacedCount += 1;
        continue;
      }

      // ------------------------------------------------------
      // TRY NORMALIZED ENTRY SEARCH
      // ------------------------------------------------------

      let matchedEntry = null;

      zip.forEach(
        (relativePath) => {
          if (
            matchedEntry ||
            relativePath.endsWith("/")
          ) {
            return;
          }

          const normalizedEntry =
            normalizePath(
              relativePath
            );

          if (
            normalizedEntry ===
            targetPath
          ) {
            matchedEntry =
              relativePath;
          }
        }
      );

      if (matchedEntry) {
        zip.file(
          matchedEntry,
          fix.fixed_code
        );

        replacedCount += 1;
      } else {
        skippedCount += 1;
      }
    }


    // --------------------------------------------------------
    // ADD PHASE 4 MANIFEST
    // --------------------------------------------------------

    const manifest = {
      tool: "SentinelForge AI",
      phase: "Phase 4",
      repository:
        data?.filename ||
        originalFile.name,
      original_repository_preserved: true,
      second_security_scan_performed: false,
      validation_status:
        data?.validation_status ||
        "Validation preparation completed.",
      fixes_generated:
        repositoryFixes.length,
      fixes_applied:
        replacedCount,
      fixes_not_applied:
        skippedCount,
    };

    zip.file(
      "sentinelforge-phase4-report.json",
      JSON.stringify(
        manifest,
        null,
        2
      )
    );


    // --------------------------------------------------------
    // GENERATE ZIP
    // --------------------------------------------------------

    setZipStatus(
      "Creating fixed repository ZIP..."
    );

    const outputBlob =
      await zip.generateAsync({
        type: "blob",
        compression: "DEFLATE",
        compressionOptions: {
          level: 6,
        },
      });


    // --------------------------------------------------------
    // DOWNLOAD
    // --------------------------------------------------------

    const safeName =
      String(
        data?.filename ||
          originalFile.name
      )
        .replace(/\.zip$/i, "")
        .replace(/[^\w.-]+/g, "_");

    downloadBlob(
      outputBlob,
      `SentinelForge_${safeName}_Fixed_Repository.zip`
    );

    setZipDownloaded(true);

    setZipStatus(
      `Fixed repository ZIP downloaded. ${replacedCount} file(s) replaced.`
    );
  }


  // ==========================================================
  // EMAIL REPORT
  // ==========================================================

  async function sendEmailReport(data) {
    setEmailStatus(
      "Preparing email security report..."
    );

    // --------------------------------------------------------
    // CHECK EMAILJS CONFIGURATION
    // --------------------------------------------------------

    if (
      !EMAILJS_SERVICE_ID ||
      !EMAILJS_TEMPLATE_ID ||
      !EMAILJS_PUBLIC_KEY
    ) {
      throw new Error(
        "EmailJS environment variables are not configured."
      );
    }

    // --------------------------------------------------------
    // BUILD EMAIL HTML
    // --------------------------------------------------------

    const reportFindings =
      data?.findings || [];

    const reportAssessments =
      data?.risk_assessments || [];

    const reportRisk =
      data?.overall_risk || {};

    const reportAI =
      data?.ai_analysis || "";

    const reportFixes =
      data?.fixes || [];


    let findingsHtml = "";

    if (
      reportFindings.length === 0
    ) {
      findingsHtml =
        "<p>No security vulnerabilities were detected.</p>";
    } else {
      findingsHtml =
        reportFindings
          .map(
            (finding, index) => {
              const assessment =
                reportAssessments[
                  index
                ] || {};

              const vulnerability =
                getVulnerabilityType(
                  finding,
                  assessment
                );

              const severity =
                getSeverity(
                  finding,
                  assessment
                );

              const path =
                finding?.path ||
                "Unknown";

              const line =
                getLine(finding);

              const cwe =
                getCwe(
                  finding,
                  assessment
                );

              const riskScore =
                getRiskScore(
                  assessment
                );

              const recommendation =
                assessment?.recommendation ||
                "Not specified";

              return `
                <div style="
                  border:1px solid #e5e7eb;
                  border-radius:10px;
                  padding:16px;
                  margin-bottom:14px;
                  font-family:Arial,sans-serif;
                ">
                  <h3 style="margin-top:0;">
                    ${escapeHtml(
                      vulnerability
                    )}
                  </h3>

                  <p>
                    <strong>Severity:</strong>
                    ${escapeHtml(
                      severity
                    )}
                  </p>

                  <p>
                    <strong>File:</strong>
                    ${escapeHtml(
                      path
                    )}
                  </p>

                  <p>
                    <strong>Line:</strong>
                    ${escapeHtml(
                      line
                    )}
                  </p>

                  <p>
                    <strong>CWE:</strong>
                    ${escapeHtml(
                      cwe
                    )}
                  </p>

                  <p>
                    <strong>Risk Score:</strong>
                    ${escapeHtml(
                      riskScore
                    )}
                  </p>

                  <p>
                    <strong>Recommendation:</strong>
                    ${escapeHtml(
                      recommendation
                    )}
                  </p>
                </div>
              `;
            }
          )
          .join("");
    }


    const successfulFixes =
      reportFixes.filter(
        (fix) => fix?.success
      ).length;


    const roleText =
      data?.role === "student"
        ? "Student"
        : "Developer";


    const templateParams = {
      to_email:
        data?.email ||
        email,

      recipient_email:
        data?.email ||
        email,

      email:
        data?.email ||
        email,

      user_email:
        data?.email ||
        email,

      role:
        roleText,

      repository:
        data?.filename ||
        selectedFile?.name ||
        "repository.zip",

      filename:
        data?.filename ||
        selectedFile?.name ||
        "repository.zip",

      findings_count:
        reportFindings.length,

      risk_score:
        reportRisk.score ??
        reportRisk.overall_score ??
        "N/A",

      risk_level:
        reportRisk.risk_level ??
        reportRisk.level ??
        "N/A",

      fixes_generated:
        successfulFixes,

      findings_html:
        findingsHtml,

      ai_analysis:
        reportAI,

      validation_status:
        data?.validation_status ||
        "Validation preparation completed. No second security scan was performed.",

      subject:
        `SentinelForge AI Security Report - ${
          data?.filename ||
          "Repository"
        }`,
    };


    setEmailStatus(
      "Sending security report..."
    );


    // --------------------------------------------------------
    // SEND THROUGH EMAILJS
    // --------------------------------------------------------

    await emailjs.send(
      EMAILJS_SERVICE_ID,
      EMAILJS_TEMPLATE_ID,
      templateParams,
      {
        publicKey:
          EMAILJS_PUBLIC_KEY,
      }
    );


    setEmailStatus(
      `Security report sent successfully to ${
        data?.email || email
      }.`
    );
  }


  // ==========================================================
  // RESET
  // ==========================================================

  function resetAnalysis() {
    setRole("student");
    setEmail("");
    setSelectedFile(null);

    setRunning(false);
    setCompleted(false);

    setError("");

    setScanData(null);

    setStages(
      DEFAULT_STAGES
    );

    setEmailStatus("");
    setReportStatus("");
    setZipStatus("");

    setPdfDownloaded(false);
    setZipDownloaded(false);

    const input =
      document.getElementById(
        "repository-upload"
      );

    if (input) {
      input.value = "";
    }
  }


  // ==========================================================
  // RENDER
  // ==========================================================

  return (
    <div className="app-shell">

      {/* ================================================== */}
      {/* HEADER */}
      {/* ================================================== */}

      <header className="app-header">

        <div className="brand-block">
          <div className="brand-mark">
            SF
          </div>

          <div>
            <h1>
              SentinelForge AI
            </h1>

            <p>
              Autonomous Repository Security
            </p>
          </div>
        </div>

        <div className="phase-badge">
          PHASE 4
        </div>

      </header>


      {/* ================================================== */}
      {/* MAIN */}
      {/* ================================================== */}

      <main className="main-container">

        {!completed && (
          <>
            {/* ============================================ */}
            {/* HERO */}
            {/* ============================================ */}

            <section className="hero-section">

              <div className="hero-content">

                <span className="hero-label">
                  AUTONOMOUS SECURITY
                </span>

                <h2>
                  Secure your repository
                  <br />
                  with one click.
                </h2>

                <p>
                  Upload your repository and let
                  SentinelForge AI automatically
                  detect vulnerabilities, assess risk,
                  analyze the code, generate fixes,
                  prepare the final report and deliver
                  the results.
                </p>

              </div>

            </section>


            {/* ============================================ */}
            {/* INPUT CARD */}
            {/* ============================================ */}

            <section className="input-card">

              <div className="section-heading">
                <div>
                  <span>
                    STEP 1
                  </span>

                  <h3>
                    Tell us about you
                  </h3>
                </div>
              </div>


              {/* ROLE */}

              <div className="input-group">

                <label>
                  Role
                </label>

                <div className="role-grid">

                  <button
                    type="button"
                    className={
                      role === "student"
                        ? "role-option active"
                        : "role-option"
                    }
                    onClick={() =>
                      setRole(
                        "student"
                      )
                    }
                    disabled={running}
                  >
                    <span className="role-icon">
                      🎓
                    </span>

                    <span>
                      <strong>
                        Student
                      </strong>

                      <small>
                        Educational security report
                      </small>
                    </span>
                  </button>


                  <button
                    type="button"
                    className={
                      role === "developer"
                        ? "role-option active"
                        : "role-option"
                    }
                    onClick={() =>
                      setRole(
                        "developer"
                      )
                    }
                    disabled={running}
                  >
                    <span className="role-icon">
                      💻
                    </span>

                    <span>
                      <strong>
                        Developer
                      </strong>

                      <small>
                        Technical security report
                      </small>
                    </span>
                  </button>

                </div>

              </div>


              {/* EMAIL */}

              <div className="input-group">

                <label htmlFor="email">
                  Email address
                </label>

                <input
                  id="email"
                  type="email"
                  placeholder="you@example.com"
                  value={email}
                  onChange={(event) =>
                    setEmail(
                      event.target.value
                    )
                  }
                  disabled={running}
                />

              </div>


              {/* FILE */}

              <div className="input-group">

                <label>
                  Repository ZIP
                </label>

                <label
                  htmlFor="repository-upload"
                  className={
                    running
                      ? "upload-box disabled"
                      : "upload-box"
                  }
                >

                  <input
                    id="repository-upload"
                    type="file"
                    accept=".zip,application/zip"
                    onChange={
                      handleFileChange
                    }
                    disabled={running}
                  />

                  <span className="upload-icon">
                    ↑
                  </span>

                  <strong>
                    {selectedFile
                      ? selectedFile.name
                      : "Choose repository ZIP"}
                  </strong>

                  <small>
                    Maximum 50 MB
                  </small>

                </label>

              </div>


              {/* ERROR */}

              {error && (
                <div className="error-box">
                  {error}
                </div>
              )}


              {/* START */}

              <button
                type="button"
                className="start-button"
                onClick={
                  startAutonomousAnalysis
                }
                disabled={running}
              >

                {running ? (
                  <>
                    <span className="spinner" />
                    Autonomous Analysis Running...
                  </>
                ) : (
                  <>
                    Start Autonomous Analysis
                    <span>
                      →
                    </span>
                  </>
                )}

              </button>

            </section>


            {/* ============================================ */}
            {/* PIPELINE PREVIEW */}
            {/* ============================================ */}

            <section className="pipeline-card">

              <div className="section-heading">
                <div>
                  <span>
                    AUTONOMOUS PIPELINE
                  </span>

                  <h3>
                    One request. Full security workflow.
                  </h3>
                </div>
              </div>


              <div className="pipeline-preview">

                {DEFAULT_STAGES.map(
                  (stage, index) => (
                    <div
                      className="preview-stage"
                      key={stage.id}
                    >

                      <div className="preview-number">
                        {index + 1}
                      </div>

                      <div>
                        <strong>
                          {stage.title}
                        </strong>
                      </div>

                    </div>
                  )
                )}

              </div>

            </section>
          </>
        )}


        {/* ================================================== */}
        {/* RUNNING */}
        {/* ================================================== */}

        {running && (
          <section className="results-section">

            <div className="processing-card">

              <div className="processing-icon">
                <span className="spinner large" />
              </div>

              <h2>
                SentinelForge AI is working
              </h2>

              <p>
                Your repository is being processed
                autonomously. Please keep this page open.
              </p>

              <div className="processing-note">
                Detection → Risk → AI Analysis →
                Auto-Fix → Validation Preparation
              </div>

            </div>

          </section>
        )}


        {/* ================================================== */}
        {/* RESULTS */}
        {/* ================================================== */}

        {completed && scanData && (
          <section className="results-section">

            {/* ============================================ */}
            {/* SUCCESS HEADER */}
            {/* ============================================ */}

            <div className="results-header">

              <div>
                <span className="hero-label">
                  ANALYSIS COMPLETED
                </span>

                <h2>
                  Your repository security
                  analysis is ready.
                </h2>

                <p>
                  {scanData.filename}
                </p>
              </div>

              <button
                type="button"
                className="secondary-button"
                onClick={resetAnalysis}
              >
                New Analysis
              </button>

            </div>


            {/* ============================================ */}
            {/* PIPELINE */}
            {/* ============================================ */}

            <div className="results-card">

              <div className="section-heading">
                <div>
                  <span>
                    PIPELINE
                  </span>

                  <h3>
                    Autonomous execution
                  </h3>
                </div>
              </div>


              <div className="pipeline-list">

                {stages.map(
                  (stage, index) => {

                    const status =
                      stage.status ||
                      "pending";

                    return (
                      <div
                        className={`pipeline-item ${status}`}
                        key={
                          stage.id ||
                          index
                        }
                      >

                        <div className="pipeline-icon">

                          {status ===
                            "completed" && (
                            <span>
                              ✓
                            </span>
                          )}

                          {status ===
                            "running" && (
                            <span className="spinner" />
                          )}

                          {status ===
                            "skipped" && (
                            <span>
                              –
                            </span>
                          )}

                          {status ===
                            "pending" && (
                            <span>
                              {index + 1}
                            </span>
                          )}

                        </div>

                        <div className="pipeline-content">

                          <strong>
                            {stage.title}
                          </strong>

                          {stage.message && (
                            <p>
                              {stage.message}
                            </p>
                          )}

                        </div>

                        <div className="pipeline-status">
                          {status}
                        </div>

                      </div>
                    );
                  }
                )}

              </div>

            </div>


            {/* ============================================ */}
            {/* OVERVIEW */}
            {/* ============================================ */}

            <div className="stats-grid">

              <div className="stat-card">
                <span>
                  FINDINGS
                </span>

                <strong>
                  {findings.length}
                </strong>
              </div>

              <div className="stat-card">
                <span>
                  RISK SCORE
                </span>

                <strong>
                  {
                    overallRisk.score ??
                    overallRisk.overall_score ??
                    "N/A"
                  }
                </strong>
              </div>

              <div className="stat-card">
                <span>
                  RISK LEVEL
                </span>

                <strong>
                  {
                    overallRisk.risk_level ??
                    overallRisk.level ??
                    "N/A"
                  }
                </strong>
              </div>

              <div className="stat-card">
                <span>
                  FIXES GENERATED
                </span>

                <strong>
                  {successfulFixCount}
                </strong>
              </div>

            </div>


            {/* ============================================ */}
            {/* SEVERITY */}
            {/* ============================================ */}

            <div className="results-card">

              <div className="section-heading">
                <div>
                  <span>
                    SEVERITY
                  </span>

                  <h3>
                    Finding distribution
                  </h3>
                </div>
              </div>

              <div className="severity-grid">

                <div>
                  <strong>
                    {severityCounts.CRITICAL}
                  </strong>
                  <span>
                    Critical
                  </span>
                </div>

                <div>
                  <strong>
                    {severityCounts.HIGH}
                  </strong>
                  <span>
                    High
                  </span>
                </div>

                <div>
                  <strong>
                    {severityCounts.MEDIUM}
                  </strong>
                  <span>
                    Medium
                  </span>
                </div>

                <div>
                  <strong>
                    {severityCounts.LOW}
                  </strong>
                  <span>
                    Low
                  </span>
                </div>

                <div>
                  <strong>
                    {severityCounts.INFO}
                  </strong>
                  <span>
                    Info
                  </span>
                </div>

              </div>

            </div>


            {/* ============================================ */}
            {/* AI ANALYSIS */}
            {/* ============================================ */}

            <div className="results-card">

              <div className="section-heading">
                <div>
                  <span>
                    GROQ AI
                  </span>

                  <h3>
                    Security analysis
                  </h3>
                </div>
              </div>

              <div className="analysis-box">
                {aiAnalysis ||
                  "No AI analysis returned."}
              </div>

            </div>


            {/* ============================================ */}
            {/* FINDINGS */}
            {/* ============================================ */}

            <div className="results-card">

              <div className="section-heading">
                <div>
                  <span>
                    SECURITY FINDINGS
                  </span>

                  <h3>
                    Detected vulnerabilities
                  </h3>
                </div>
              </div>


              {findings.length === 0 ? (
                <div className="secure-box">
                  ✓ No security vulnerabilities
                  were detected.
                </div>
              ) : (
                <div className="finding-list">

                  {findings.map(
                    (finding, index) => {
                      const assessment =
                        riskAssessments[
                          index
                        ] || {};

                      const vulnerability =
                        getVulnerabilityType(
                          finding,
                          assessment
                        );

                      const severity =
                        getSeverity(
                          finding,
                          assessment
                        );

                      return (
                        <article
                          className="finding-card"
                          key={index}
                        >

                          <div className="finding-header">

                            <div>
                              <span className="finding-number">
                                FINDING {index + 1}
                              </span>

                              <h4>
                                {vulnerability}
                              </h4>
                            </div>

                            <span className="severity-badge">
                              {severity}
                            </span>

                          </div>


                          <div className="finding-meta">

                            <div>
                              <span>
                                File
                              </span>

                              <strong>
                                {finding?.path ||
                                  "Unknown"}
                              </strong>
                            </div>

                            <div>
                              <span>
                                Line
                              </span>

                              <strong>
                                {getLine(
                                  finding
                                )}
                              </strong>
                            </div>

                            <div>
                              <span>
                                CWE
                              </span>

                              <strong>
                                {getCwe(
                                  finding,
                                  assessment
                                )}
                              </strong>
                            </div>

                            <div>
                              <span>
                                Risk
                              </span>

                              <strong>
                                {getRiskScore(
                                  assessment
                                )}
                              </strong>
                            </div>

                          </div>


                          <div className="finding-message">

                            <span>
                              Semgrep Message
                            </span>

                            <p>
                              {getMessage(
                                finding
                              )}
                            </p>

                          </div>


                          {finding?.source_code && (
                            <details className="source-details">

                              <summary>
                                View source context
                              </summary>

                              <pre>
                                {finding.source_code}
                              </pre>

                            </details>
                          )}

                        </article>
                      );
                    }
                  )}

                </div>
              )}

            </div>


            {/* ============================================ */}
            {/* FIX SUMMARY */}
            {/* ============================================ */}

            <div className="results-card">

              <div className="section-heading">
                <div>
                  <span>
                    AI AUTO-FIX
                  </span>

                  <h3>
                    Remediation preparation
                  </h3>
                </div>
              </div>


              <div className="fix-summary">

                <div>
                  <strong>
                    {successfulFixCount}
                  </strong>

                  <span>
                    fixes generated
                  </span>
                </div>

                <div>
                  <strong>
                    {failedFixCount}
                  </strong>

                  <span>
                    fixes unavailable
                  </span>
                </div>

              </div>


              <div className="note-box">
                The original uploaded repository
                was not modified. Generated fixes
                are placed into a new repository ZIP.
                Phase 4 does not perform a second
                security scan, so the fixes are not
                claimed as security-verified.
              </div>

            </div>


            {/* ============================================ */}
            {/* DELIVERY */}
            {/* ============================================ */}

            <div className="results-card">

              <div className="section-heading">
                <div>
                  <span>
                    DELIVERY
                  </span>

                  <h3>
                    Your generated outputs
                  </h3>
                </div>
              </div>


              <div className="delivery-grid">

                <div
                  className={
                    pdfDownloaded
                      ? "delivery-item done"
                      : "delivery-item"
                  }
                >
                  <span>
                    {pdfDownloaded
                      ? "✓"
                      : "•"}
                  </span>

                  <div>
                    <strong>
                      Security Report PDF
                    </strong>

                    <small>
                      {reportStatus ||
                        "Generated after analysis"}
                    </small>
                  </div>
                </div>


                <div
                  className={
                    zipDownloaded
                      ? "delivery-item done"
                      : "delivery-item"
                  }
                >
                  <span>
                    {zipDownloaded
                      ? "✓"
                      : "•"}
                  </span>

                  <div>
                    <strong>
                      Fixed Repository ZIP
                    </strong>

                    <small>
                      {zipStatus ||
                        "Generated after auto-fix"}
                    </small>
                  </div>
                </div>


                <div
                  className={
                    emailStatus.startsWith(
                      "Security report sent"
                    )
                      ? "delivery-item done"
                      : "delivery-item"
                  }
                >
                  <span>
                    {emailStatus.startsWith(
                      "Security report sent"
                    )
                      ? "✓"
                      : "•"}
                  </span>

                  <div>
                    <strong>
                      Email Report
                    </strong>

                    <small>
                      {emailStatus ||
                        "Sent to your email"}
                    </small>
                  </div>
                </div>

              </div>

            </div>


            {/* ============================================ */}
            {/* VALIDATION NOTICE */}
            {/* ============================================ */}

            <div className="validation-banner">

              <strong>
                Validation status
              </strong>

              <p>
                {scanData.validation_status ||
                  "Validation preparation completed. No second security scan was performed."}
              </p>

            </div>

          </section>
        )}

      </main>


      {/* ================================================== */}
      {/* FOOTER */}
      {/* ================================================== */}

      <footer className="app-footer">

        <span>
          SentinelForge AI
        </span>

        <span>
          Autonomous Security Platform
        </span>

      </footer>

    </div>
  );
}