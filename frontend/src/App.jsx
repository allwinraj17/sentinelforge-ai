import { useState, useRef, useEffect } from "react";
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

const PROJECT_TITLE =
  "A Multi-Agent System for Automated Software Repository Security Analysis";

// ============================================================
// AUTONOMOUS PIPELINE — MUST MATCH BACKEND STAGE IDS EXACTLY
// ============================================================

const PIPELINE_STAGES = [
  { id: "repository", title: "Repository Upload", message: "Repository ZIP received successfully." },
  { id: "extract", title: "Secure Extraction", message: "Safely extracting repository contents." },
  { id: "understanding", title: "Repository Understanding", message: "Analyzing repository structure, languages and important files." },
  { id: "semgrep", title: "Semgrep Detection", message: "Semgrep is scanning the repository for security vulnerabilities." },
  { id: "secret", title: "Secret Detection", message: "Checking for hardcoded secrets and sensitive credentials." },
  {
  id: "dependency",
  title: "Dependency Analysis",
  message: "Analyzing repository dependencies separately from source-code findings."
},
  { id: "ml_triage", title: "ML Vulnerability Triage", message: "Classifying findings as likely vulnerabilities." },
  { id: "ml_classification", title: "ML Classification", message: "Predicting vulnerability categories." },
  { id: "ml_severity", title: "ML Severity Prediction", message: "Predicting finding severity." },
  { id: "ml_priority", title: "ML Priority Prediction", message: "Predicting remediation priority." },
  { id: "ml_code_context", title: "ML Code Context", message: "Analyzing the security context of affected code." },
  { id: "ml_similarity", title: "ML Duplicate Similarity", message: "Comparing related security findings." },
  { id: "ml_fix_recommendation", title: "ML Fix Recommendation", message: "Generating a security fix recommendation." },
  { id: "risk", title: "Risk Assessment", message: "Calculating deterministic security risk." },
  { id: "compliance", title: "Compliance Mapping", message: "Mapping findings to relevant OWASP / compliance categories." },
  { id: "fix", title: "AI Auto-Fix", message: "Generating secure remediation for supported findings." },
  { id: "validation", title: "Fix Validation", message: "Checking generated remediation artifacts." },
  { id: "report", title: "Security Report", message: "Preparing the final security report." },
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

function getFindingId(finding, index) {
  return (
    finding?.finding_id ||
    finding?.findingId ||
    finding?.id ||
    `F${String(index + 1).padStart(3, "0")}`
  );
}

function getSeverity(finding, assessment) {
  return (
    assessment?.severity ||
    finding?.extra?.severity ||
    finding?.severity ||
    "UNKNOWN"
  );
}

function getVulnerabilityType(finding, assessment) {
  let type =
    assessment?.vulnerability_type ||
    finding?.extra?.metadata?.vulnerability_class ||
    finding?.extra?.metadata?.["vulnerability-class"] ||
    finding?.check_id ||
    "Security Vulnerability";

  if (Array.isArray(type)) {
    type = type.join(", ");
  }

  return type;
}

function getLine(finding) {
  return finding?.start?.line || finding?.line || "Unknown";
}

function getMessage(finding) {
  return (
    finding?.extra?.message ||
    finding?.message ||
    "Security issue detected."
  );
}

function getCwe(finding, assessment) {
  let cwe =
    assessment?.cwe ||
    finding?.extra?.metadata?.cwe ||
    "";

  if (Array.isArray(cwe)) {
    cwe = cwe.join(", ");
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

function getRiskLevel(overallRisk, riskAssessments) {
  if (overallRisk?.risk_level) {
    return String(overallRisk.risk_level).toUpperCase();
  }

  if (overallRisk?.level) {
    return String(overallRisk.level).toUpperCase();
  }

  if (typeof overallRisk === "string") {
    return overallRisk.toUpperCase();
  }

  if (riskAssessments?.length > 0) {
    const levels = riskAssessments
      .map((item) => item?.risk_level || item?.level || "")
      .filter(Boolean);

    if (levels.length > 0) {
      const priority = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

      for (const priorityLevel of priority) {
        const found = levels.find(
          (level) => String(level).toUpperCase() === priorityLevel
        );

        if (found) {
          return String(found).toUpperCase();
        }
      }

      return String(levels[0]).toUpperCase();
    }
  }

  const score = Number(overallRisk?.score ?? overallRisk?.overall_score);

  if (!Number.isNaN(score)) {
  if (score >= 10) return "CRITICAL";
  if (score >= 8) return "HIGH";
  if (score >= 5) return "MEDIUM";
  if (score >= 2.5) return "LOW";
  if (score > 0) return "INFO";

  return "SECURE";
}
  return "N/A";
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

function getRepositoryName(scanData, selectedFile) {
  return scanData?.filename || selectedFile?.name || "repository.zip";
}

function getSafeRepositoryName(name) {
  return String(name)
    .replace(/\.zip$/i, "")
    .replace(/[^\w.-]+/g, "_");
}

// ============================================================
// ML DISPLAY HELPERS
// ============================================================

/**
 * Looks up an ML agent's result for a given finding.
 *
 * Priority:
 *  1. The value already attached directly onto the finding by the
 *     backend (finding[key] / finding.ml_results[key]) — this is the
 *     authoritative, finding_id-based mapping done server-side.
 *  2. A finding_id match inside the raw scanData.<key>.results array.
 *  3. A finding_index match inside that same array (fallback only).
 */
function getMlDataForFinding(scanData, finding, key, index) {
  // ------------------------------------------------------------
  // Helper: the backend may return either:
  //
  // 1. Direct ML payload:
  //    {
  //      predicted_type: "SQL Injection"
  //    }
  //
  // 2. Full finding containing the ML payload:
  //    {
  //      finding_id: "F001",
  //      finding_index: 0,
  //      ml_classification: {
  //        predicted_type: "SQL Injection"
  //      }
  //    }
  //
  // Normalize both formats to the actual ML payload.
  // ------------------------------------------------------------
  function unwrapMlResult(value) {
    if (!value || typeof value !== "object") {
      return null;
    }

    // Backend currently returns the complete finding object
    // inside finding[key].
    if (
      value[key] &&
      typeof value[key] === "object" &&
      !Array.isArray(value[key])
    ) {
      return value[key];
    }

    // Already-normalized ML result.
    return value;
  }

  // ------------------------------------------------------------
  // 1. Prefer the ML result already attached directly to the
  //    finding by the backend.
  // ------------------------------------------------------------
  if (finding?.[key]) {
    return unwrapMlResult(finding[key]);
  }

  // ------------------------------------------------------------
  // 2. Check finding.ml_results[key].
  // ------------------------------------------------------------
  if (finding?.ml_results?.[key]) {
    return unwrapMlResult(finding.ml_results[key]);
  }

  // ------------------------------------------------------------
  // 3. Check the raw top-level scan response.
  // ------------------------------------------------------------
  const bucket =
    scanData?.ml_results?.[key] ??
    scanData?.[key];

  const results = Array.isArray(bucket?.results)
    ? bucket.results
    : [];

  const findingId = getFindingId(finding, index);

  // ------------------------------------------------------------
  // 4. Match by stable finding ID.
  // ------------------------------------------------------------
  const byId = results.find(
    (item) =>
      item &&
      (
        item.finding_id === findingId ||
        item.findingId === findingId ||
        item.id === findingId
      )
  );

  if (byId) {
    return unwrapMlResult(byId);
  }

  // ------------------------------------------------------------
  // 5. Fallback to finding index.
  // ------------------------------------------------------------
  const byIndex = results.find(
    (item) =>
      item &&
      Number(item.finding_index) === index
  );

  if (byIndex) {
    return unwrapMlResult(byIndex);
  }

  return null;
}
function formatMlConfidence(value) {
  const number = Number(value);

  if (Number.isNaN(number)) {
    return "N/A";
  }

  const percentage = number <= 1 ? number * 100 : number;

  return `${percentage.toFixed(2)}%`;
}

function getMlConfidenceLevel(value) {
  const number = Number(value);

  if (Number.isNaN(number)) {
    return "Confidence unavailable";
  }

  const normalized = number > 1 ? number / 100 : number;

  if (normalized >= 0.8) {
    return "High Confidence";
  }

  if (normalized >= 0.5) {
    return "Medium Confidence";
  }

  return "Low Confidence";
}

function getMlDisplayValue(value, fallback = "N/A") {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }

  return String(value);
}

function maskSecretValue(value) {
  const str = String(value ?? "");

  if (str.length <= 8) {
    return "••••••••";
  }

  return `${str.slice(0, 4)}••••••••${str.slice(-4)}`;
}

// ============================================================
// APP
// ============================================================

export default function App() {

  // ==========================================================
  // INPUT
  // ==========================================================

  const [role, setRole] = useState("student");
  const [email, setEmail] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);

  // ==========================================================
  // ANALYSIS
  // ==========================================================

  const [running, setRunning] = useState(false);
  const [completed, setCompleted] = useState(false);
  const [error, setError] = useState("");
  const [scanData, setScanData] = useState(null);

  // ==========================================================
  // PROGRESS
  // ==========================================================

  const [progressStage, setProgressStage] = useState(-1);
  const [progressMessage, setProgressMessage] = useState("");
  const [progressPercent, setProgressPercent] = useState(0);
  const [scanJobId, setScanJobId] = useState("");
  const [liveStages, setLiveStages] = useState([]);

  const progressPollRef = useRef(null);

  // ==========================================================
  // DOWNLOAD / EMAIL
  // ==========================================================

  const [pdfDownloaded, setPdfDownloaded] = useState(false);
  const [zipDownloaded, setZipDownloaded] = useState(false);
  const [pdfStatus, setPdfStatus] = useState("");
  const [zipStatus, setZipStatus] = useState("");
  const [emailStatus, setEmailStatus] = useState("");

  const emailStartedRef = useRef(false);
  const progressTimersRef = useRef([]);

  // ==========================================================
  // CLEANUP TIMERS
  // ==========================================================

  useEffect(() => {
    return () => {
      clearProgressTimers();

      if (progressPollRef.current) {
        clearInterval(progressPollRef.current);
        progressPollRef.current = null;
      }
    };
  }, []);

  // ==========================================================
  // FILE CHANGE
  // ==========================================================

  function handleFileChange(event) {
    const file = event.target.files?.[0] || null;

    setSelectedFile(file);
    setError("");
    setCompleted(false);
    setScanData(null);
    setProgressStage(-1);
    setProgressMessage("");
    setProgressPercent(0);
    setScanJobId("");
    setLiveStages([]);

    if (progressPollRef.current) {
      clearInterval(progressPollRef.current);
      progressPollRef.current = null;
    }

    setPdfDownloaded(false);
    setZipDownloaded(false);
    setPdfStatus("");
    setZipStatus("");
    setEmailStatus("");
    emailStartedRef.current = false;
  }

  // ==========================================================
  // PROGRESS
  // ==========================================================

  function updateProgress(stageIndex, message) {
    setProgressStage(stageIndex);
    setProgressMessage(message);
  }

  function clearProgressTimers() {
    progressTimersRef.current.forEach((timer) => clearTimeout(timer));
    progressTimersRef.current = [];
  }

  // ==========================================================
  // START AUTONOMOUS ANALYSIS
  // ==========================================================

  async function startAutonomousAnalysis() {

    setError("");
    setCompleted(false);
    setScanData(null);
    setPdfDownloaded(false);
    setZipDownloaded(false);
    setPdfStatus("");
    setZipStatus("");
    setEmailStatus("");
    setScanJobId("");
    setLiveStages([]);
    setProgressStage(-1);
    setProgressMessage("");
    setProgressPercent(0);
    emailStartedRef.current = false;

    if (!role) {
      setError("Please select your role.");
      return;
    }

    if (!email.trim()) {
      setError("Please enter your email address.");
      return;
    }

    if (!email.includes("@")) {
      setError("Please enter a valid email address.");
      return;
    }

    if (!selectedFile) {
      setError("Please upload a repository ZIP file.");
      return;
    }

    if (!selectedFile.name.toLowerCase().endsWith(".zip")) {
      setError("Only ZIP repository files are supported.");
      return;
    }

    const maxSize = 50 * 1024 * 1024;

    if (selectedFile.size > maxSize) {
      setError("Repository ZIP must be smaller than 50 MB.");
      return;
    }

    setRunning(true);
    updateProgress(
      0,
      "Uploading repository and starting the backend security pipeline..."
    );

    try {
      const formData = new FormData();
      formData.append("role", role);
      formData.append("email", email.trim());
      formData.append("file", selectedFile);

      // ------------------------------------------------------
      // POST /scan/start
      // ------------------------------------------------------

      const startResponse = await fetch(`${API_URL}/scan/start`, {
        method: "POST",
        body: formData,
      });

      let startData = null;

      try {
        startData = await startResponse.json();
      } catch {
        throw new Error(
          `Backend returned an invalid response (${startResponse.status}).`
        );
      }

      if (!startResponse.ok || !startData?.success || !startData?.scan_id) {
        throw new Error(
          startData?.detail ||
          startData?.message ||
          "Unable to start the security analysis."
        );
      }

      const scanId = startData.scan_id;
      setScanJobId(scanId);

      // ------------------------------------------------------
      // GET /scan/progress/{scan_id}
      // ------------------------------------------------------

      const pollStatus = async () => {
        const statusResponse = await fetch(
          `${API_URL}/scan/progress/${scanId}`,
          {
            method: "GET",
            cache: "no-store",
          }
        );

        let statusData = null;

        try {
          statusData = await statusResponse.json();
        } catch {
          throw new Error(
            `Progress endpoint returned an invalid response (${statusResponse.status}).`
          );
        }

        if (!statusResponse.ok) {
          throw new Error(
            statusData?.detail ||
            statusData?.error ||
            "Unable to read security scan progress."
          );
        }

        // All 18 backend-driven stages, in backend order.
        const stages = Array.isArray(statusData?.stages)
          ? statusData.stages
          : [];

        setLiveStages(stages);

        const activeIndex = stages.findIndex(
          (stage) => stage?.status === "running"
        );

        const pendingIndex = stages.findIndex(
          (stage) => stage?.status === "pending"
        );

        const currentIndex =
          activeIndex >= 0
            ? activeIndex
            : pendingIndex >= 0
              ? pendingIndex
              : Math.max(0, stages.length - 1);

        setProgressStage(currentIndex);

        const currentStage =
          stages[activeIndex >= 0 ? activeIndex : currentIndex];

        setProgressMessage(
          currentStage?.message ||
          statusData?.message ||
          (statusData?.status === "completed"
            ? "Security analysis completed successfully."
            : "Security agents are processing the repository...")
        );

        // Backend-computed overall progress percentage — never simulated.
        if (typeof statusData?.progress === "number") {
          setProgressPercent(
            Math.max(0, Math.min(100, statusData.progress))
          );
        }

        if (statusData?.status === "completed") {
          if (progressPollRef.current) {
            clearInterval(progressPollRef.current);
            progressPollRef.current = null;
          }

          const result = statusData?.data;

          if (!result?.success) {
            setRunning(false);
            throw new Error(
              result?.message || "Autonomous analysis failed."
            );
          }

          setScanData(result);
          setLiveStages(stages);
          setProgressStage(Math.max(0, stages.length - 1));
          setProgressPercent(100);
          setProgressMessage(
            "Autonomous analysis completed successfully."
          );
          setRunning(false);

          setTimeout(() => {
            setCompleted(true);
          }, 350);

          return true;
        }

        if (statusData?.status === "error") {
          throw new Error(
            statusData?.error || "Autonomous analysis failed."
          );
        }

        return false;
      };

      const finishedImmediately = await pollStatus();

      if (!finishedImmediately) {
        progressPollRef.current = setInterval(async () => {
          try {
            const finished = await pollStatus();

            if (finished && progressPollRef.current) {
              clearInterval(progressPollRef.current);
              progressPollRef.current = null;
            }
          } catch (pollError) {
            if (progressPollRef.current) {
              clearInterval(progressPollRef.current);
              progressPollRef.current = null;
            }

            console.error("Security scan polling error:", pollError);

            setError(
              pollError?.message ||
              "Unable to monitor the security analysis."
            );
            setProgressStage(-1);
            setProgressMessage("");
            setRunning(false);
          }
        }, 700);
      }

    } catch (requestError) {
      console.error("Autonomous analysis error:", requestError);

      if (progressPollRef.current) {
        clearInterval(progressPollRef.current);
        progressPollRef.current = null;
      }

      setError(
        requestError?.message || "Something went wrong during analysis."
      );

      setProgressMessage("");
      setProgressStage(-1);
      setRunning(false);
    }
  }

  // ==========================================================
  // BUILD SECURITY REPORT PDF
  // ==========================================================

  function buildSecurityReportPDF(data) {

    const reportRole = data?.role || role;
    const reportFindings = data?.findings || [];
    const reportAssessments = data?.risk_assessments || [];
    const reportRisk = data?.overall_risk || {};
    const reportFixes = data?.fixes || [];
    const reportSecrets = data?.secrets || [];
    const reportDependencies =
      data?.dependency_analysis?.vulnerabilities || [];

    const repositoryName = getRepositoryName(data, selectedFile);

    const doc = new jsPDF({ unit: "mm", format: "a4" });

    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();

    let y = 18;

    function addPageIfNeeded(requiredHeight = 10) {
      if (y + requiredHeight > pageHeight - 16) {
        doc.addPage();
        y = 18;
      }
    }

    function writeText(text, options = {}) {
      const fontSize = options.fontSize || 10;
      const bold = options.bold || false;
      const lineHeight = options.lineHeight || 5;
      const maxWidth = options.maxWidth || pageWidth - 30;

      doc.setFontSize(fontSize);
      doc.setFont("helvetica", bold ? "bold" : "normal");

      const lines = doc.splitTextToSize(String(text ?? ""), maxWidth);

      addPageIfNeeded(lines.length * lineHeight + 2);

      doc.text(lines, 15, y);

      y += lines.length * lineHeight;
    }

    // ========================================================
    // REPORT TITLE
    // ========================================================

    doc.setFont("helvetica", "bold");
    doc.setFontSize(17);

    const titleLines = doc.splitTextToSize(PROJECT_TITLE, pageWidth - 30);

    doc.text(titleLines, 15, y);
    y += titleLines.length * 7;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);

    doc.text(
      "Automated Software Repository Security Analysis Report",
      15,
      y
    );

    y += 8;

    doc.line(15, y, pageWidth - 15, y);
    y += 8;

    // ========================================================
    // GENERAL INFORMATION
    // ========================================================

    writeText(`Repository: ${repositoryName}`, { bold: true, fontSize: 11 });

    writeText(
      `Role: ${reportRole === "student" ? "Student" : "Developer"}`
    );

    writeText(`Email: ${data?.email || email}`);

    writeText(`Vulnerabilities Detected: ${reportFindings.length}`);

    writeText(`Secrets Detected: ${reportSecrets.length}`);

    writeText(`Vulnerable Dependencies: ${reportDependencies.length}`);

    writeText(
      `Overall Risk Score: ${
        reportRisk.score ?? reportRisk.overall_score ?? "N/A"
      }`
    );

    writeText(
      `Overall Risk Level: ${getRiskLevel(reportRisk, reportAssessments)}`
    );

    y += 5;

    // ========================================================
    // STUDENT REPORT
    // ========================================================

    if (reportRole === "student") {

      writeText("Security Explanation", { fontSize: 14, bold: true });

      if (reportFindings.length === 0) {

        writeText(
          "No security vulnerabilities were detected in the analyzed repository."
        );

      } else {

        reportFindings.forEach((finding, index) => {

          const assessment =
            finding?.official_risk ||
            finding?.risk_assessment ||
            reportAssessments[index] ||
            {};

          writeText(
            `Vulnerability ${index + 1} [${getFindingId(finding, index)}]: ${getVulnerabilityType(finding, assessment)}`,
            { fontSize: 12, bold: true }
          );

          writeText(
            `Where: ${finding?.path || "Unknown"} at line ${getLine(finding)}`
          );

          writeText(`What was detected: ${getMessage(finding)}`);

          writeText(
            `Possible attack path: ${
              assessment?.exploitability ||
              "The vulnerability may be exploitable depending on application exposure and input handling."
            }`
          );

          writeText(
            `Impact: ${
              assessment?.impact ||
              "Potential security impact depends on how the affected component is used."
            }`
          );

          writeText(
            `Prevention / Fix: ${
              assessment?.recommendation ||
              "Use secure coding practices and validate untrusted input."
            }`
          );

          y += 4;

        });

      }

    } else {

      // ======================================================
      // DEVELOPER REPORT
      // ======================================================

      writeText("Technical Security Findings", { fontSize: 14, bold: true });

      if (reportFindings.length === 0) {

        writeText("No security vulnerabilities were detected.");

      } else {

        reportFindings.forEach((finding, index) => {

          const assessment =
            finding?.official_risk ||
            finding?.risk_assessment ||
            reportAssessments[index] ||
            {};

          writeText(
            `Finding ${index + 1} [${getFindingId(finding, index)}]: ${getVulnerabilityType(finding, assessment)}`,
            { fontSize: 12, bold: true }
          );

          writeText(`Semgrep Rule: ${finding?.check_id || "Unknown"}`);
          writeText(`File: ${finding?.path || "Unknown"}`);
          writeText(`Line: ${getLine(finding)}`);
          writeText(`Severity: ${getSeverity(finding, assessment)}`);
          writeText(`CWE: ${getCwe(finding, assessment)}`);
          writeText(`Risk Score: ${getRiskScore(assessment)}`);
          writeText(`Risk Level: ${getRiskLevel(assessment, [])}`);
          writeText(`Semgrep Message: ${getMessage(finding)}`);
          writeText(`Impact: ${assessment?.impact || "Not specified"}`);

          writeText(
            `Exploitability: ${assessment?.exploitability || "Not specified"}`
          );

          writeText(
            `Recommended Remediation: ${
              assessment?.recommendation || "Not specified"
            }`
          );

          if (finding?.source_code) {

            writeText("Source Context:", { bold: true });

            writeText(finding.source_code, {
              fontSize: 8,
              lineHeight: 4,
            });

          }

          y += 4;

        });

      }

    }

    // ========================================================
    // SECRETS
    // ========================================================

    writeText("Detected Secrets", { fontSize: 14, bold: true });

    if (reportSecrets.length === 0) {

      writeText("No hardcoded secrets or credentials were detected.");

    } else {

      reportSecrets.forEach((secret, index) => {

        writeText(
          `Secret ${index + 1}: ${
            secret?.type || secret?.rule_id || "Potential credential"
          }`,
          { bold: true }
        );

        writeText(`File: ${secret?.path || secret?.file || "Unknown"}`);
        writeText(`Line: ${getLine(secret)}`);
        writeText(`Value: ${maskSecretValue(secret?.value || secret?.match)}`);

        y += 2;

      });

    }

    // ========================================================
    // DEPENDENCIES
    // ========================================================

    writeText("Dependency Analysis", { fontSize: 14, bold: true });

    if (reportDependencies.length === 0) {

      writeText("No known vulnerable dependencies were detected.");

    } else {

      reportDependencies.forEach((dependency, index) => {

        writeText(
          `Dependency ${index + 1}: ${
            dependency?.package || dependency?.name || "Unknown package"
          } ${dependency?.version ? `(v${dependency.version})` : ""}`,
          { bold: true }
        );

        writeText(
          `Vulnerability: ${
            dependency?.vulnerability_id ||
            dependency?.cve ||
            "Not specified"
          }`
        );

        writeText(
          `Severity: ${dependency?.severity || "Not specified"}`
        );

        writeText(
          `Recommended Fix: ${
            dependency?.recommended_fix ||
            dependency?.fixed_version ||
            "Upgrade to a patched version."
          }`
        );

        y += 2;

      });

    }

    // ========================================================
    // AUTO-FIX SUMMARY
    // ========================================================

    writeText("AI Auto-Fix Summary", { fontSize: 14, bold: true });

    const successfulFixes = reportFixes.filter((fix) => fix?.success).length;
    const unavailableFixes = reportFixes.filter((fix) => !fix?.success).length;

    writeText(`Corrected files generated: ${successfulFixes}`);
    writeText(`Files without generated remediation: ${unavailableFixes}`);

    writeText(
      "AI-assisted remediation was generated for vulnerable source files where automated correction was available."
    );

    // ========================================================
    // VALIDATION
    // ========================================================

    writeText("Validation Agent", { fontSize: 14, bold: true });

    const validation = data?.validation || {};

    writeText(
      validation?.message || "Remediation artifact checks completed."
    );

    if (validation?.status) {
      writeText(`Validation Status: ${validation.status}`);
    }

    // ========================================================
    // PIPELINE
    // ========================================================

    writeText("Autonomous Processing Pipeline", {
      fontSize: 14,
      bold: true,
    });

    writeText(PIPELINE_STAGES.map((stage) => stage.title).join(" → "));

    // ========================================================
    // FOOTER
    // ========================================================

    addPageIfNeeded(15);

    y += 5;

    doc.line(15, y, pageWidth - 15, y);

    y += 6;

    writeText("Generated automatically by SentinelForge AI.", {
      fontSize: 8,
    });

    writeText("Original uploaded repository remains unchanged.", {
      fontSize: 8,
    });

    return doc;
  }

  // ==========================================================
  // PDF DOWNLOAD
  // ==========================================================

  function downloadSecurityReport() {

    if (!scanData) {
      return;
    }

    try {

      setPdfStatus("Generating security report...");

      const doc = buildSecurityReportPDF(scanData);

      const repositoryName = getRepositoryName(scanData, selectedFile);
      const safeName = getSafeRepositoryName(repositoryName);

      doc.save(`Security_Report_${safeName}.pdf`);

      setPdfDownloaded(true);
      setPdfStatus("Security report downloaded successfully.");

    } catch (pdfError) {

      console.error("PDF generation error:", pdfError);

      setPdfStatus(
        `PDF download failed: ${pdfError?.message || "Unknown error"}`
      );

    }
  }

  // ==========================================================
  // FIXED REPOSITORY ZIP
  // ==========================================================

  async function downloadFixedRepository() {

    if (!selectedFile) {
      setZipStatus("Original repository ZIP is unavailable.");
      return;
    }

    if (!scanData) {
      setZipStatus("Analysis results are unavailable.");
      return;
    }

    try {

      setZipStatus("Preparing fixed repository...");

      // Prefer the backend-generated fixed ZIP so the manifest and
      // fix application logic always match the pipeline that ran
      // server-side. Fall back to a client-side rebuild if that
      // endpoint is unavailable for any reason.

      if (scanJobId) {

        try {

          const response = await fetch(
            `${API_URL}/scan/download-fixed/${scanJobId}`
          );

          if (response.ok) {

            const blob = await response.blob();

            const repositoryName = getRepositoryName(
              scanData,
              selectedFile
            );

            const safeName = getSafeRepositoryName(repositoryName);

            downloadBlob(blob, `Fixed_Repository_${safeName}.zip`);

            setZipDownloaded(true);
            setZipStatus("Fixed repository downloaded from the backend.");

            return;
          }

        } catch (backendZipError) {

          console.warn(
            "Backend fixed-ZIP download failed, falling back to client-side rebuild:",
            backendZipError
          );

        }

      }

      const originalBuffer = await selectedFile.arrayBuffer();
      const zip = await JSZip.loadAsync(originalBuffer);

      const fixes = scanData?.fixes || [];

      let replacedCount = 0;
      let skippedCount = 0;

      for (const fix of fixes) {

        if (!fix?.success || !fix?.fixed_code || !fix?.original_path) {
          skippedCount += 1;
          continue;
        }

        const targetPath = normalizePath(fix.original_path);

        if (!targetPath) {
          skippedCount += 1;
          continue;
        }

        if (zip.file(targetPath)) {
          zip.file(targetPath, fix.fixed_code);
          replacedCount += 1;
          continue;
        }

        const dotPath = `./${targetPath}`;

        if (zip.file(dotPath)) {
          zip.file(dotPath, fix.fixed_code);
          replacedCount += 1;
          continue;
        }

        let matchedPath = null;

        zip.forEach((relativePath) => {
          if (matchedPath || relativePath.endsWith("/")) {
            return;
          }

          if (normalizePath(relativePath) === targetPath) {
            matchedPath = relativePath;
          }
        });

        if (matchedPath) {
          zip.file(matchedPath, fix.fixed_code);
          replacedCount += 1;
        } else {
          skippedCount += 1;
        }

      }

      const manifest = {
        project_title: PROJECT_TITLE,
        repository: scanData?.filename || selectedFile.name,
        analysis_type: "Autonomous Multi-Agent Security Analysis",
        generated_fixes: fixes.length,
        successful_fixes: fixes.filter((fix) => fix?.success).length,
        files_replaced: replacedCount,
        files_not_replaced: skippedCount,
        original_repository_modified: false,
        validation_agent: scanData?.validation || "completed",
      };

      zip.file(
        "security-analysis-manifest.json",
        JSON.stringify(manifest, null, 2)
      );

      setZipStatus("Creating fixed repository ZIP...");

      const outputBlob = await zip.generateAsync({
        type: "blob",
        compression: "DEFLATE",
        compressionOptions: { level: 6 },
      });

      const repositoryName = getRepositoryName(scanData, selectedFile);
      const safeName = getSafeRepositoryName(repositoryName);

      downloadBlob(outputBlob, `Fixed_Repository_${safeName}.zip`);

      setZipDownloaded(true);

      setZipStatus(
        `Fixed repository downloaded. ${replacedCount} file(s) replaced.`
      );

    } catch (zipError) {

      console.error("ZIP generation error:", zipError);

      setZipStatus(
        `Fixed repository download failed: ${
          zipError?.message || "Unknown error"
        }`
      );

    }
  }

  // ==========================================================
  // EMAIL
  // ==========================================================

  async function sendAutomaticEmail(data) {

    if (!EMAILJS_SERVICE_ID || !EMAILJS_TEMPLATE_ID || !EMAILJS_PUBLIC_KEY) {
      throw new Error("Email service is not configured.");
    }

    const reportFindings = data?.findings || [];
    const reportAssessments = data?.risk_assessments || [];
    const reportFixes = data?.fixes || [];
    const reportRisk = data?.overall_risk || {};

    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;

    reportFindings.forEach((finding, index) => {

      const assessment =
        finding?.official_risk ||
        finding?.risk_assessment ||
        reportAssessments[index] ||
        {};

      const severity = String(
        getSeverity(finding, assessment)
      ).toUpperCase();

      if (severity === "CRITICAL") {
        critical += 1;
      } else if (severity === "HIGH") {
        high += 1;
      } else if (severity === "MEDIUM") {
        medium += 1;
      } else if (severity === "LOW") {
        low += 1;
      }

    });

    let findingsHtml = "";

    if (reportFindings.length === 0) {

      findingsHtml = `
        <div style="
          padding:16px;
          border:1px solid #d1d5db;
          border-radius:10px;
          background:#f9fafb;
          font-family:Arial,sans-serif;
        ">
          <strong>No security vulnerabilities were detected.</strong>
          <p style="margin-bottom:0;">
            The analyzed repository did not produce any security findings.
          </p>
        </div>
      `;

    } else {

      findingsHtml = reportFindings
        .map((finding, index) => {

          const assessment =
            finding?.official_risk ||
            finding?.risk_assessment ||
            reportAssessments[index] ||
            {};

          const severity = getSeverity(finding, assessment);
          const vulnerabilityType = getVulnerabilityType(finding, assessment);
          const filePath = finding?.path || "Unknown";
          const line = getLine(finding);
          const cwe = getCwe(finding, assessment);
          const riskScore = getRiskScore(assessment);
          const message = getMessage(finding);
          const recommendation = assessment?.recommendation || "Not specified";
          const impact = assessment?.impact || "Not specified";
          const exploitability = assessment?.exploitability || "Not specified";
          const findingId = getFindingId(finding, index);

          return `
            <div style="
              border:1px solid #e5e7eb;
              border-radius:10px;
              padding:18px;
              margin-bottom:15px;
              font-family:Arial,sans-serif;
              background:#ffffff;
            ">

              <h3 style="margin-top:0; margin-bottom:12px;">
                ${escapeHtml(findingId)}: ${escapeHtml(vulnerabilityType)}
              </h3>

              <p><strong>Severity:</strong> ${escapeHtml(severity)}</p>
              <p><strong>File:</strong> ${escapeHtml(filePath)}</p>
              <p><strong>Line:</strong> ${escapeHtml(line)}</p>
              <p><strong>CWE:</strong> ${escapeHtml(cwe)}</p>
              <p><strong>Risk Score:</strong> ${escapeHtml(riskScore)}</p>

              <p>
                <strong>Security Message:</strong><br>
                ${escapeHtml(message)}
              </p>

              <p>
                <strong>Impact:</strong><br>
                ${escapeHtml(impact)}
              </p>

              <p>
                <strong>Exploitability:</strong><br>
                ${escapeHtml(exploitability)}
              </p>

              <p style="margin-bottom:0;">
                <strong>Recommended Remediation:</strong><br>
                ${escapeHtml(recommendation)}
              </p>

            </div>
          `;

        })
        .join("");

    }

    const successfulFixes = reportFixes.filter((fix) => fix?.success).length;
    const repositoryName = getRepositoryName(data, selectedFile);
    const riskScore = reportRisk.score ?? reportRisk.overall_score ?? "N/A";
    const riskLevel = getRiskLevel(reportRisk, reportAssessments);

    const templateParams = {
      to_email: data?.email || email,
      recipient_email: data?.email || email,
      email: data?.email || email,
      user_email: data?.email || email,

      role: data?.role === "student" ? "Student" : "Developer",
      project_title: PROJECT_TITLE,
      repository: repositoryName,
      filename: repositoryName,

      overall_risk: riskLevel,
      risk_score: riskScore,
      total_findings: reportFindings.length,

      critical,
      high,
      medium,
      low,

      report: findingsHtml,

      findings_count: reportFindings.length,
      risk_level: riskLevel,
      fixes_generated: successfulFixes,
      findings_html: findingsHtml,

      validation_status:
        data?.validation?.message ||
        "Remediation artifact checks completed.",

      subject: `Repository Security Report - ${repositoryName}`,
    };

    await emailjs.send(
      EMAILJS_SERVICE_ID,
      EMAILJS_TEMPLATE_ID,
      templateParams,
      { publicKey: EMAILJS_PUBLIC_KEY }
    );

    return true;
  }

  // ==========================================================
  // TRIGGER EMAIL ONCE
  // ==========================================================

  async function triggerAutomaticEmail() {

    if (!scanData || emailStartedRef.current) {
      return;
    }

    emailStartedRef.current = true;

    try {

      setEmailStatus("Sending report to your email...");

      await sendAutomaticEmail(scanData);

      setEmailStatus(
        `Security report sent successfully to ${scanData?.email || email}.`
      );

    } catch (emailError) {

      console.error("Email delivery error:", emailError);

      setEmailStatus(
        `Email delivery failed: ${emailError?.message || "Unknown error"}`
      );

    }
  }

  // ==========================================================
  // AUTOMATIC EMAIL AFTER RESULTS
  // ==========================================================

  useEffect(() => {

    if (completed && scanData && !emailStartedRef.current) {
      triggerAutomaticEmail();
    }

  }, [completed, scanData]);

  // ==========================================================
  // RESET
  // ==========================================================

  function resetAnalysis() {

    clearProgressTimers();

    setRole("student");
    setEmail("");
    setSelectedFile(null);
    setRunning(false);
    setCompleted(false);
    setError("");
    setScanData(null);
    setProgressStage(-1);
    setProgressMessage("");
    setProgressPercent(0);
    setScanJobId("");
    setLiveStages([]);
    setPdfDownloaded(false);
    setZipDownloaded(false);
    setPdfStatus("");
    setZipStatus("");
    setEmailStatus("");
    emailStartedRef.current = false;

    const input = document.getElementById("repository-upload");

    if (input) {
      input.value = "";
    }
  }

  // ==========================================================
  // CALCULATED RESULTS
  // ==========================================================

  const findings = scanData?.findings || [];
  const secrets = scanData?.secrets || [];
  const dependencies = scanData?.dependency_analysis?.vulnerabilities || [];
  const assessments = scanData?.risk_assessments || [];
  const fixes = scanData?.fixes || [];

  const successfulFixes = fixes.filter((fix) => fix?.success).length;

  const riskLevel = getRiskLevel(scanData?.overall_risk, assessments);

  const stagesForDisplay =
    liveStages.length > 0
      ? liveStages
      : PIPELINE_STAGES.map((stage) => ({
          ...stage,
          status: stage.id === "repository" ? "completed" : "pending",
        }));

  const completedStageCount = stagesForDisplay.filter(
    (stage) => stage?.status === "completed" || stage?.status === "skipped"
  ).length;

  const activeStage = stagesForDisplay.find(
    (stage) => stage?.status === "running"
  );

  const failedStage = stagesForDisplay.find(
    (stage) => stage?.status === "failed" || stage?.status === "error"
  );

  const computedProgressPercent =
    progressPercent > 0
      ? progressPercent
      : stagesForDisplay.length > 0
        ? Math.round((completedStageCount / stagesForDisplay.length) * 100)
        : 0;

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

          <div className="brand-mark">AI</div>

          <div className="brand-text">
            <h1>Security Analysis</h1>
            <p>Automated repository security platform</p>
          </div>

        </div>

      </header>

      {/* ================================================== */}
      {/* MAIN */}
      {/* ================================================== */}

      <main className="main-container">

        {/* ================================================== */}
        {/* START SCREEN */}
        {/* ================================================== */}

        {!running && !completed && (
          <>

            <section className="hero-section">

              <div className="hero-content">

                <span className="hero-label">SOFTWARE SECURITY</span>

                <h2>{PROJECT_TITLE}</h2>

                <p>
                  Upload a repository ZIP and let the autonomous security
                  workflow detect vulnerabilities, assess risk, generate
                  AI-assisted remediation, validate the result and prepare
                  your security report.
                </p>

              </div>

            </section>

            <section className="input-card">

              <div className="section-heading">

                <div>
                  <span>START ANALYSIS</span>
                  <h3>Repository Security Analysis</h3>
                </div>

              </div>

              {/* ROLE */}

              <fieldset className="input-group" disabled={running}>

                <legend>Select your role</legend>

                <div className="role-grid">

                  <button
                    type="button"
                    id="role-student"
                    className={
                      role === "student"
                        ? "role-option active"
                        : "role-option"
                    }
                    aria-pressed={role === "student"}
                    onClick={() => setRole("student")}
                    disabled={running}
                  >
                    <span className="role-icon" aria-hidden="true">🎓</span>
                    <span>
                      <strong>Student</strong>
                      <small>Educational security report</small>
                    </span>
                  </button>

                  <button
                    type="button"
                    id="role-developer"
                    className={
                      role === "developer"
                        ? "role-option active"
                        : "role-option"
                    }
                    aria-pressed={role === "developer"}
                    onClick={() => setRole("developer")}
                    disabled={running}
                  >
                    <span className="role-icon" aria-hidden="true">💻</span>
                    <span>
                      <strong>Developer</strong>
                      <small>Technical security report</small>
                    </span>
                  </button>

                </div>

              </fieldset>

              {/* EMAIL */}

              <div className="input-group">

                <label htmlFor="email">Email address</label>

                <input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  placeholder="you@example.com"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  disabled={running}
                  required
                />

              </div>

              {/* ZIP */}

              <div className="input-group">

                <label htmlFor="repository-upload">Repository ZIP</label>

                <label
                  htmlFor="repository-upload"
                  className="upload-box"
                >

                  <input
                    id="repository-upload"
                    name="repository-upload"
                    type="file"
                    accept=".zip,application/zip"
                    autoComplete="off"
                    onChange={handleFileChange}
                    disabled={running}
                  />

                  <span className="upload-icon" aria-hidden="true">↑</span>

                  <strong>
                    {selectedFile ? selectedFile.name : "Choose repository ZIP"}
                  </strong>

                  <small>Maximum 50 MB</small>

                </label>

              </div>

              {/* ERROR */}

              {error && (
                <div className="error-box" role="alert">
                  {error}
                </div>
              )}

              {/* START */}

              <button
                type="button"
                className="start-button"
                onClick={startAutonomousAnalysis}
                disabled={running}
              >
                Start Autonomous Analysis
                <span aria-hidden="true">→</span>
              </button>

            </section>

          </>
        )}

        {/* ================================================== */}
        {/* PROGRESS SCREEN */}
        {/* ================================================== */}

        {running && (

          <section className="progress-page">

            <div className="progress-card">

              <span className="hero-label">LIVE SECURITY ANALYSIS</span>

              <h2>Securing your repository...</h2>

              <p>
                Progress is reported directly by the backend security
                pipeline.
              </p>

              <div className="progress-bar">
                <div
                  className="progress-fill"
                  style={{ width: `${computedProgressPercent}%` }}
                />
              </div>

              <div className="progress-current">
                <span className="progress-spinner" aria-hidden="true" />
                <span>
                  {failedStage
                    ? `Stage failed: ${failedStage.name || failedStage.title}`
                    : progressMessage ||
                      activeStage?.message ||
                      "Waiting for the backend pipeline..."}
                </span>
              </div>

              <div className="progress-meta">
                {completedStageCount} of {stagesForDisplay.length} stages
                completed • {computedProgressPercent}%
                {scanJobId ? ` • Scan ${scanJobId.slice(0, 8)}` : ""}
              </div>

              <div className="progress-list">

                {stagesForDisplay.map((stage, index) => {

                  const rawStatus = stage?.status;

                  const status =
                    rawStatus === "completed" || rawStatus === "skipped"
                      ? "completed"
                      : rawStatus === "running"
                        ? "active"
                        : rawStatus === "failed" || rawStatus === "error"
                          ? "failed"
                          : "pending";

                  const meta =
                    PIPELINE_STAGES.find((item) => item.id === stage?.id) ||
                    {};

                  return (

                    <div
                      className={`progress-stage ${status}`}
                      key={stage?.id || index}
                    >

                      <div className="progress-stage-icon">

                        {status === "completed" && <span>✓</span>}
                        {status === "active" && (
                          <span className="mini-spinner" />
                        )}
                        {status === "failed" && <span>✕</span>}
                        {status === "pending" && <span>{index + 1}</span>}

                      </div>

                      <div>

                        <strong>
                          {stage?.name || meta.title || `Stage ${index + 1}`}
                        </strong>

                        {(status === "active" || status === "failed") && (
                          <small>
                            {stage?.message ||
                              (status === "failed"
                                ? "This stage failed."
                                : "Processing...")}
                          </small>
                        )}

                      </div>

                    </div>

                  );

                })}

              </div>

            </div>

          </section>

        )}

        {/* ================================================== */}
        {/* RESULTS */}
        {/* ================================================== */}

        {completed && scanData && (

          <section className="results-section">

            {/* RESULT HEADER */}

            <div className="results-header">

              <div>
                <span className="hero-label">ANALYSIS COMPLETED</span>
                <h2>Security results are ready.</h2>
                <p>{getRepositoryName(scanData, selectedFile)}</p>
              </div>

              <button
                type="button"
                className="secondary-button"
                onClick={resetAnalysis}
              >
                New Analysis
              </button>

            </div>

            {/* PROJECT */}

            <div className="results-card">
              <div className="project-title-box">
                <span>PROJECT</span>
                <strong>{PROJECT_TITLE}</strong>
              </div>
            </div>

            {/* AUTONOMOUS PIPELINE */}

            <div className="results-card">

              <div className="section-heading">
                <div>
                  <span>AUTONOMOUS PIPELINE</span>
                  <h3>Completed security workflow</h3>
                </div>
              </div>

              <div className="pipeline-list">

                {(scanData?.pipeline || stagesForDisplay).map(
                  (stage, index) => {

                    const meta =
                      PIPELINE_STAGES.find((item) => item.id === stage?.id) ||
                      {};

                    const status = stage.status || "completed";

                    return (

                      <div
                        className={`pipeline-item ${status}`}
                        key={stage.id || index}
                      >

                        <div className="pipeline-icon">
                          {status === "skipped"
                            ? "–"
                            : status === "failed" || status === "error"
                              ? "✕"
                              : "✓"}
                        </div>

                        <div className="pipeline-content">
                          <strong>{stage.name || meta.title}</strong>
                          {stage.message && <p>{stage.message}</p>}
                        </div>

                        <div className="pipeline-status">{status}</div>

                      </div>

                    );

                  }
                )}

                <div
                  className={`pipeline-item ${
                    emailStatus.startsWith("Security report sent")
                      ? "completed"
                      : "active"
                  }`}
                >

                  <div className="pipeline-icon">
                    {emailStatus.startsWith("Security report sent")
                      ? "✓"
                      : "✉"}
                  </div>

                  <div className="pipeline-content">
                    <strong>Email Delivery</strong>
                    <p>{emailStatus || "Preparing email delivery..."}</p>
                  </div>

                  <div className="pipeline-status">
                    {emailStatus.startsWith("Security report sent")
                      ? "sent"
                      : "processing"}
                  </div>

                </div>

              </div>

            </div>

            {/* STATS */}

            <div className="stats-grid">

              <div className="stat-card">
                <span>FINDINGS</span>
                <strong>{findings.length}</strong>
              </div>

              <div className="stat-card">
                <span>SECRETS</span>
                <strong>{secrets.length}</strong>
              </div>

              <div className="stat-card">
  <span>DEPENDENCY ISSUES</span>
  <strong>{dependencies.length}</strong>
</div>
              <div className="stat-card">
                <span>RISK LEVEL</span>
                <strong>{riskLevel}</strong>
              </div>

              <div className="stat-card">
                <span>AI FIXES</span>
                <strong>{successfulFixes}</strong>
              </div>

            </div>

            {/* ================================================== */}
            {/* ML SECURITY INTELLIGENCE */}
            {/* ================================================== */}

            <div className="results-card ml-intelligence-card">

              <div className="section-heading">
                <div>
                  <span>ML SECURITY INTELLIGENCE</span>
                  <h3>Machine-learning analysis of detected findings</h3>
                  <p className="ml-section-description">
                    Seven specialized ML agents provide additional
                    intelligence after Semgrep detection, mapped by stable
                    finding ID.
                  </p>
                </div>
              </div>

              {findings.length === 0 ? (

                <div className="secure-box">
                  No findings were available for ML security intelligence.
                </div>

              ) : (

                <div className="ml-finding-list">

                  {findings.map((finding, index) => {

                    const findingId = getFindingId(finding, index);

                    const triage = getMlDataForFinding(
                      scanData,
                      finding,
                      "ml_triage",
                      index
                    );

                    const classification = getMlDataForFinding(
                      scanData,
                      finding,
                      "ml_classification",
                      index
                    );

                    const mlSeverity = getMlDataForFinding(
                      scanData,
                      finding,
                      "ml_severity",
                      index
                    );

                    const priority = getMlDataForFinding(
                      scanData,
                      finding,
                      "ml_priority",
                      index
                    );

                    const context = getMlDataForFinding(
                      scanData,
                      finding,
                      "ml_code_context",
                      index
                    );

                    const recommendation = getMlDataForFinding(
                      scanData,
                      finding,
                      "ml_fix_recommendation",
                      index
                    );

                    const similarityResults = Array.isArray(
                      scanData?.ml_results?.ml_similarity?.results ??
                        scanData?.ml_similarity?.results
                    )
                      ? scanData?.ml_results?.ml_similarity?.results ??
                        scanData?.ml_similarity?.results
                      : [];

                    const relatedSimilarity =
                      similarityResults
                        .filter(
                          (item) =>
                            item?.finding_1_id === findingId ||
                            item?.finding_2_id === findingId ||
                            item?.finding_1_index === index ||
                            item?.finding_2_index === index
                        )
                        .sort(
                          (a, b) =>
                            Number(b?.similarity_percentage ?? b?.similarity_probability ?? 0) -
                            Number(a?.similarity_percentage ?? a?.similarity_probability ?? 0)
                        )[0] || null;

                    const triageProbability =
                      triage?.vulnerability_probability;

                    const triageClassification = triage?.classification;

                    const triageConfidence =
                      triage?.confidence_level ??
                      getMlConfidenceLevel(triageProbability);

                    const predictedType =
                      classification?.predicted_type ??
                      classification?.vulnerability_type;

                    const predictedSeverity =
                      mlSeverity?.predicted_severity ?? mlSeverity?.severity;

                    const severityConfidence = mlSeverity?.confidence;

                    const predictedPriority =
                      priority?.predicted_priority ?? priority?.priority;

                    const priorityConfidence = priority?.confidence;

                    const predictedContext =
                      context?.predicted_context ?? context?.context;

                    const contextConfidence = context?.confidence;

                    const similarityScore =
                      relatedSimilarity?.similarity_percentage ??
                      relatedSimilarity?.similarity_probability;

                    const similarityLabel =
                      relatedSimilarity?.duplicate !== undefined
                        ? relatedSimilarity.duplicate
                          ? "Likely duplicate"
                          : "Not a duplicate"
                        : relatedSimilarity?.similarity_level ??
                          relatedSimilarity?.classification ??
                          relatedSimilarity?.label;

                    const recommendedFix =
                      recommendation?.recommended_fix ??
                      recommendation?.fix_recommendation;

                    const recommendationConfidence =
                      recommendation?.confidence;

                    const assessment =
                      finding?.official_risk ||
                      finding?.risk_assessment ||
                      assessments[index] ||
                      {};

                    return (

                      <article
                        className="ml-finding-panel"
                        key={`ml-${findingId}-${index}`}
                      >

                        <div className="ml-finding-panel-header">

                          <div>
                            <span className="finding-number">
                              {findingId} · ML ANALYSIS
                            </span>
                            <h4>
                              {getVulnerabilityType(finding, assessment)}
                            </h4>
                          </div>

                          <span className="ml-model-count">7 ML AGENTS</span>

                        </div>

                        <div className="ml-grid">

                          <div className="ml-item">
                            <span>Vulnerability Triage</span>
                            <strong>
                              {getMlDisplayValue(
                                triageClassification,
                                "Analysis unavailable"
                              )}
                            </strong>
                            <small>
                              Probability:{" "}
                              {formatMlConfidence(triageProbability)}
                              <br />
                              {triageConfidence}
                            </small>
                          </div>

                          <div className="ml-item">
                            <span>Vulnerability Classification</span>
                            <strong>
                              {getMlDisplayValue(
                                predictedType,
                                "Analysis unavailable"
                              )}
                            </strong>
                            <small>ML predicted vulnerability category</small>
                          </div>

                          <div className="ml-item">
                            <span>ML Severity Prediction</span>
                            <strong>
                              {getMlDisplayValue(predictedSeverity, "N/A")}
                            </strong>
                            <small>
                              Confidence:{" "}
                              {formatMlConfidence(severityConfidence)}
                            </small>
                          </div>

                          <div className="ml-item">
                            <span>ML Priority Prediction</span>
                            <strong>
                              {getMlDisplayValue(predictedPriority, "N/A")}
                            </strong>
                            <small>
                              Confidence:{" "}
                              {formatMlConfidence(priorityConfidence)}
                            </small>
                          </div>

                          <div className="ml-item">
                            <span>Code Context Analysis</span>
                            <strong>
                              {getMlDisplayValue(predictedContext, "N/A")}
                            </strong>
                            <small>
                              Context confidence:{" "}
                              {formatMlConfidence(contextConfidence)}
                            </small>
                          </div>

                          <div className="ml-item">
                            <span>Duplicate Vulnerability Similarity</span>
                            <strong>
                              {getMlDisplayValue(
                                similarityLabel,
                                "No comparison"
                              )}
                            </strong>
                            <small>
                              Similarity: {formatMlConfidence(similarityScore)}
                            </small>
                          </div>

                          <div className="ml-item ml-item-wide">
                            <span>Fix Recommendation</span>
                            <strong>
                              {getMlDisplayValue(
                                recommendedFix,
                                "No recommendation available"
                              )}
                            </strong>
                            <small>
                              Confidence:{" "}
                              {formatMlConfidence(recommendationConfidence)}
                            </small>
                          </div>

                        </div>

                      </article>

                    );

                  })}

                </div>

              )}

            </div>

            {/* ================================================== */}
            {/* SECURITY FINDINGS */}
            {/* ================================================== */}

            <div className="results-card">

              <div className="section-heading">
                <div>
                  <span>SECURITY FINDINGS</span>
                  <h3>Vulnerabilities detected</h3>
                </div>
              </div>

              {findings.length === 0 ? (

                <div className="secure-box">
                  ✓ No security vulnerabilities were detected.
                </div>

              ) : (

                <div className="finding-list">

                  {findings.map((finding, index) => {

                    const findingId = getFindingId(finding, index);

                    const assessment =
                      finding?.official_risk ||
                      finding?.risk_assessment ||
                      assessments[index] ||
                      {};

                    return (

                      <article className="finding-card" key={findingId}>

                        <div className="finding-header">

                          <div>
                            <span className="finding-number">
                              {findingId}
                            </span>
                            <h4>
                              {getVulnerabilityType(finding, assessment)}
                            </h4>
                          </div>

                          <span className="severity-badge">
                            {getSeverity(finding, assessment)}
                          </span>

                        </div>

                        <div className="finding-meta">

                          <div>
                            <span>File</span>
                            <strong>{finding?.path || "Unknown"}</strong>
                          </div>

                          <div>
                            <span>Line</span>
                            <strong>{getLine(finding)}</strong>
                          </div>

                          <div>
                            <span>CWE</span>
                            <strong>{getCwe(finding, assessment)}</strong>
                          </div>

                          <div>
                            <span>Official Risk Score</span>
                            <strong>{getRiskScore(assessment)}</strong>
                          </div>

                        </div>

                        <div className="finding-message">
                          <span>Semgrep Message</span>
                          <p>{getMessage(finding)}</p>
                        </div>

                        {assessment?.recommendation && (
                          <div className="finding-message">
                            <span>Recommended Remediation</span>
                            <p>{assessment.recommendation}</p>
                          </div>
                        )}

                        {finding?.source_code && (
                          <details className="source-details">
                            <summary>View source context</summary>
                            <pre>{finding.source_code}</pre>
                          </details>
                        )}

                      </article>

                    );

                  })}

                </div>

              )}

            </div>

            {/* ================================================== */}
            {/* SECRETS DETECTED */}
            {/* ================================================== */}

            <div className="results-card">

              <div className="section-heading">
                <div>
                  <span>SECRET DETECTION</span>
                  <h3>Hardcoded secrets and credentials</h3>
                </div>
              </div>

              {secrets.length === 0 ? (

                <div className="secure-box">
                  ✓ No hardcoded secrets or credentials were detected.
                </div>

              ) : (

                <div className="finding-list">

                  {secrets.map((secret, index) => {

                    const secretId = getFindingId(
                      secret,
                      findings.length + index
                    );

                    return (

                      <article className="finding-card" key={secretId}>

                        <div className="finding-header">

                          <div>
                            <span className="finding-number">
                              {secretId}
                            </span>
                            <h4>
                              {secret?.type ||
                                secret?.rule_id ||
                                "Potential credential"}
                            </h4>
                          </div>

                          <span className="severity-badge">
                            {getSeverity(secret, {})}
                          </span>

                        </div>

                        <div className="finding-meta">

                          <div>
                            <span>File</span>
                            <strong>
                              {secret?.path || secret?.file || "Unknown"}
                            </strong>
                          </div>

                          <div>
                            <span>Line</span>
                            <strong>{getLine(secret)}</strong>
                          </div>

                          <div>
                            <span>Value</span>
                            <strong>
                              {maskSecretValue(secret?.value || secret?.match)}
                            </strong>
                          </div>

                        </div>

                        <div className="finding-message">
                          <span>Note</span>
                          <p>
                            The actual secret value is masked for your
                            protection. Rotate this credential immediately
                            and remove it from source control history.
                          </p>
                        </div>

                      </article>

                    );

                  })}

                </div>

              )}

            </div>

            {/* ================================================== */}
            {/* DEPENDENCY VULNERABILITIES */}
            {/* ================================================== */}

            <div className="results-card">

              <div className="section-heading">
                <div>
                  <span>DEPENDENCY ANALYSIS</span>
<h3>Known vulnerable packages</h3>
                </div>
              </div>

              {dependencies.length === 0 ? (

                <div className="secure-box">
                  ✓ No known vulnerable dependencies were detected.
                </div>

              ) : (

                <div className="finding-list">

                  {dependencies.map((dependency, index) => (

                    <article
                      className="finding-card"
                      key={`dep-${index}`}
                    >

                      <div className="finding-header">

                        <div>
                          <span className="finding-number">
                            DEP{String(index + 1).padStart(3, "0")}
                          </span>
                          <h4>
                            {dependency?.package ||
                              dependency?.name ||
                              "Unknown package"}
                            {dependency?.version
                              ? ` (v${dependency.version})`
                              : ""}
                          </h4>
                        </div>

                        <span className="severity-badge">
                          {dependency?.severity || "UNKNOWN"}
                        </span>

                      </div>

                      <div className="finding-meta">

                        <div>
                          <span>Vulnerability ID</span>
                          <strong>
                            {dependency?.vulnerability_id ||
                              dependency?.cve ||
                              "Not specified"}
                          </strong>
                        </div>

                        <div>
                          <span>Fixed Version</span>
                          <strong>
                            {dependency?.fixed_version || "Not specified"}
                          </strong>
                        </div>

                      </div>

                      <div className="finding-message">
                        <span>Recommended Fix</span>
                        <p>
                          {dependency?.recommended_fix ||
                            (dependency?.fixed_version
                              ? `Upgrade to version ${dependency.fixed_version}.`
                              : "Upgrade to a patched version.")}
                        </p>
                      </div>

                    </article>

                  ))}

                </div>

              )}

            </div>

            {/* ================================================== */}
            {/* AI AUTO-FIX */}
            {/* ================================================== */}

            <div className="results-card">

              <div className="section-heading">
                <div>
                  <span>AI AUTO-FIX AGENT</span>
                  <h3>Remediation results</h3>
                </div>
              </div>

              <div className="fix-summary">

                <div>
                  <strong>{successfulFixes}</strong>
                  <span>corrected files</span>
                </div>

                <div>
                  <strong>
                    {fixes.filter((fix) => !fix?.success).length}
                  </strong>
                  <span>unavailable</span>
                </div>

              </div>

              <div className="note-box">
                The AI Auto-Fix Agent generated remediation for the
                vulnerable files where automated correction was possible.
              </div>

              {fixes.length > 0 && (

                <div className="fix-list">

                  {fixes.map((fix, index) => (

                    <div className="fix-item" key={index}>

                      <div>

                        <strong>
                          {fix?.finding_id
                            ? `${fix.finding_id} — `
                            : ""}
                          {fix?.original_path || `File ${index + 1}`}
                        </strong>

                        <small>
                          {fix?.success
                            ? "Remediation generated successfully"
                            : fix?.error ||
                              "Remediation unavailable"}
                        </small>

                      </div>

                      <span>{fix?.success ? "FIXED" : "SKIPPED"}</span>

                    </div>

                  ))}

                </div>

              )}

            </div>

            {/* ================================================== */}
            {/* VALIDATION */}
            {/* ================================================== */}

            <div className="results-card">

              <div className="section-heading">
                <div>
                  <span>VALIDATION AGENT</span>
                  <h3>Remediation validation</h3>
                </div>
              </div>

              <div className="validation-agent-card">

                <div className="validation-agent-icon">✓</div>

                <div>
                  <strong>Validation completed</strong>
                  <small>
                    {scanData.validation?.message ||
                      "Remediation artifact checks completed."}
                  </small>
                </div>

              </div>

            </div>

            {/* ================================================== */}
            {/* DOWNLOADS */}
            {/* ================================================== */}

            <div className="results-card">

              <div className="section-heading">
                <div>
                  <span>DOWNLOADS</span>
                  <h3>Generated security artifacts</h3>
                </div>
              </div>

              <div className="download-grid">

                {/* PDF */}

                <div className="download-card">

                  <div className="download-icon">PDF</div>

                  <div>
                    <strong>Security Report</strong>
                    <small>Role-based security analysis report</small>
                  </div>

                  <button
                    type="button"
                    className="download-button"
                    onClick={downloadSecurityReport}
                  >
                    {pdfDownloaded ? "Download Again" : "Download Report"}
                  </button>

                  {pdfStatus && (
                    <p className="delivery-status">{pdfStatus}</p>
                  )}

                </div>

                {/* ZIP */}

                <div className="download-card">

                  <div className="download-icon">ZIP</div>

                  <div>
                    <strong>Fixed Repository</strong>
                    <small>
                      Repository containing generated remediation
                    </small>
                  </div>

                  <button
                    type="button"
                    className="download-button"
                    onClick={downloadFixedRepository}
                  >
                    {zipDownloaded ? "Download Again" : "Download Fixed ZIP"}
                  </button>

                  {zipStatus && (
                    <p className="delivery-status">{zipStatus}</p>
                  )}

                </div>

              </div>

            </div>

            {/* ================================================== */}
            {/* EMAIL */}
            {/* ================================================== */}

            <div className="results-card">

              <div className="section-heading">
                <div>
                  <span>EMAIL DELIVERY</span>
                  <h3>Automatic report delivery</h3>
                </div>
              </div>

              <div className="email-status-card">

                <div className="email-status-icon">✉</div>

                <div>
                  <strong>Security report delivery</strong>
                  <small>{emailStatus || "Preparing email..."}</small>
                </div>

              </div>

            </div>

          </section>

        )}

      </main>

      {/* ================================================== */}
      {/* FOOTER */}
      {/* ================================================== */}

      <footer className="app-footer">
        <span>{PROJECT_TITLE}</span>
        <span>Autonomous Security Analysis</span>
      </footer>

    </div>
  );
}