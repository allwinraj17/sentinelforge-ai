import { useState } from "react";
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
// PROJECT TITLE
// ============================================================

const PROJECT_TITLE =
  "A Multi-Agent System for Automated Software Repository Security Analysis";


// ============================================================
// PIPELINE STAGES
// ============================================================

const PIPELINE_STAGES = [
  {
    id: "repository",
    title: "Repository Received",
  },
  {
    id: "extract",
    title: "Repository Extraction",
  },
  {
    id: "semgrep",
    title: "Security Detection",
  },
  {
    id: "risk",
    title: "Risk Assessment",
  },
  {
    id: "fix",
    title: "AI Auto-Fix",
  },
  {
    id: "validation",
    title: "Validation Preparation",
  },
  {
    id: "report",
    title: "Report Preparation",
  },
  {
    id: "email",
    title: "Email Delivery",
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


function getSeverity(
  finding,
  assessment
) {
  return (
    assessment?.severity ||
    finding?.extra?.severity ||
    "UNKNOWN"
  );
}


function getVulnerabilityType(
  finding,
  assessment
) {
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


function getCwe(
  finding,
  assessment
) {
  let cwe =
    assessment?.cwe ||
    finding?.extra?.metadata?.cwe ||
    "";

  if (Array.isArray(cwe)) {
    cwe = cwe.join(", ");
  }

  return cwe || "Not specified";
}


function getRiskScore(
  assessment
) {
  return (
    assessment?.risk_score ??
    assessment?.score ??
    "N/A"
  );
}


function getRiskLevel(
  assessment
) {
  return (
    assessment?.risk_level ||
    assessment?.level ||
    "N/A"
  );
}


function downloadBlob(
  blob,
  filename
) {
  const url =
    URL.createObjectURL(blob);

  const link =
    document.createElement("a");

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
  // INPUT STATE
  // ----------------------------------------------------------

  const [role, setRole] =
    useState("student");

  const [email, setEmail] =
    useState("");

  const [selectedFile, setSelectedFile] =
    useState(null);


  // ----------------------------------------------------------
  // ANALYSIS STATE
  // ----------------------------------------------------------

  const [running, setRunning] =
    useState(false);

  const [completed, setCompleted] =
    useState(false);

  const [error, setError] =
    useState("");

  const [scanData, setScanData] =
    useState(null);


  // ----------------------------------------------------------
  // UI PROGRESS STATE
  // ----------------------------------------------------------

  const [progressStage, setProgressStage] =
    useState(-1);

  const [progressMessage, setProgressMessage] =
    useState("");


  // ----------------------------------------------------------
  // DELIVERY STATE
  // ----------------------------------------------------------

  const [pdfDownloaded, setPdfDownloaded] =
    useState(false);

  const [zipDownloaded, setZipDownloaded] =
    useState(false);

  const [emailStatus, setEmailStatus] =
    useState("");

  const [pdfStatus, setPdfStatus] =
    useState("");

  const [zipStatus, setZipStatus] =
    useState("");


  // ==========================================================
  // INPUT CHANGE
  // ==========================================================

  function handleFileChange(event) {

    const file =
      event.target.files?.[0] ||
      null;

    setSelectedFile(file);

    setError("");

    setCompleted(false);

    setScanData(null);

    setProgressStage(-1);

    setProgressMessage("");

    setPdfDownloaded(false);

    setZipDownloaded(false);

    setEmailStatus("");

    setPdfStatus("");

    setZipStatus("");
  }


  // ==========================================================
  // PROGRESS HELPER
  // ==========================================================

  function updateProgress(
    stageIndex,
    message
  ) {

    setProgressStage(
      stageIndex
    );

    setProgressMessage(
      message
    );
  }


  // ==========================================================
  // START ANALYSIS
  // ==========================================================

  async function startAutonomousAnalysis() {

    setError("");

    setCompleted(false);

    setScanData(null);

    setPdfDownloaded(false);

    setZipDownloaded(false);

    setEmailStatus("");

    setPdfStatus("");

    setZipStatus("");


    // --------------------------------------------------------
    // VALIDATE ROLE
    // --------------------------------------------------------

    if (!role) {

      setError(
        "Please select your role."
      );

      return;
    }


    // --------------------------------------------------------
    // VALIDATE EMAIL
    // --------------------------------------------------------

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


    // --------------------------------------------------------
    // VALIDATE FILE
    // --------------------------------------------------------

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

    updateProgress(
      0,
      "Repository received. Starting autonomous security analysis..."
    );


    try {

      // ======================================================
      // FORM DATA
      // ======================================================

      const formData =
        new FormData();

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


      // ======================================================
      // FRONTEND PROGRESS SIMULATION
      // ======================================================

      const progressTimers = [];

      progressTimers.push(
        setTimeout(() => {
          updateProgress(
            1,
            "Safely extracting repository files..."
          );
        }, 1200)
      );

      progressTimers.push(
        setTimeout(() => {
          updateProgress(
            2,
            "Semgrep is scanning the repository for security vulnerabilities..."
          );
        }, 3000)
      );

      progressTimers.push(
        setTimeout(() => {
          updateProgress(
            3,
            "Assessing vulnerability severity and overall risk..."
          );
        }, 5500)
      );

      progressTimers.push(
        setTimeout(() => {
          updateProgress(
            4,
            "AI Auto-Fix is preparing secure corrected copies..."
          );
        }, 8000)
      );


      // ======================================================
      // MASTER BACKEND REQUEST
      // ======================================================

      const response =
        await fetch(
          `${API_URL}/scan/start`,
          {
            method: "POST",
            body: formData,
          }
        );


      // ======================================================
      // CLEAR TIMERS
      // ======================================================

      progressTimers.forEach(
        (timer) => {
          clearTimeout(timer);
        }
      );


      // ======================================================
      // READ RESPONSE
      // ======================================================

      let data = null;

      try {

        data =
          await response.json();

      } catch {

        throw new Error(
          `Backend returned an invalid response (${response.status}).`
        );
      }


      if (!response.ok) {

        throw new Error(
          data?.detail ||
          "Autonomous analysis failed."
        );
      }


      if (!data?.success) {

        throw new Error(
          data?.message ||
          "Autonomous analysis failed."
        );
      }


      // ======================================================
      // REAL RESULTS
      // ======================================================

      updateProgress(
        5,
        "Preparing report and final remediation results..."
      );


      setScanData(data);


      // ======================================================
      // COMPLETE
      // ======================================================

      setTimeout(() => {

        updateProgress(
          7,
          "Analysis completed. Your results are ready."
        );

        setCompleted(true);

      }, 700);

    } catch (requestError) {

      console.error(
        "Autonomous analysis error:",
        requestError
      );


      setError(
        requestError?.message ||
        "Something went wrong during analysis."
      );


      setProgressMessage("");

    } finally {

      setRunning(false);
    }
  }


  // ==========================================================
  // BUILD PDF
  // ==========================================================

  function buildSecurityReportPDF(
    data
  ) {

    const reportRole =
      data?.role || role;

    const reportFindings =
      data?.findings || [];

    const reportAssessments =
      data?.risk_assessments || [];

    const reportRisk =
      data?.overall_risk || {};

    const repositoryName =
      data?.filename ||
      selectedFile?.name ||
      "repository.zip";


    const doc =
      new jsPDF({
        unit: "mm",
        format: "a4",
      });


    const pageWidth =
      doc.internal.pageSize.getWidth();

    const pageHeight =
      doc.internal.pageSize.getHeight();


    let y = 18;


    function addPageIfNeeded(
      height = 12
    ) {

      if (
        y + height >
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
        bold
          ? "bold"
          : "normal"
      );


      const lines =
        doc.splitTextToSize(
          String(text ?? ""),
          maxWidth
        );


      addPageIfNeeded(
        lines.length *
          lineHeight +
          3
      );


      doc.text(
        lines,
        15,
        y
      );


      y +=
        lines.length *
        lineHeight;
    }


    // ========================================================
    // TITLE
    // ========================================================

    doc.setFont(
      "helvetica",
      "bold"
    );

    doc.setFontSize(18);

    const titleLines =
      doc.splitTextToSize(
        PROJECT_TITLE,
        pageWidth - 30
      );

    doc.text(
      titleLines,
      15,
      y
    );

    y +=
      titleLines.length *
      7;


    doc.setFont(
      "helvetica",
      "normal"
    );

    doc.setFontSize(10);

    doc.text(
      "Automated Software Repository Security Analysis Report",
      15,
      y
    );

    y += 8;


    doc.line(
      15,
      y,
      pageWidth - 15,
      y
    );

    y += 9;


    // ========================================================
    // GENERAL DETAILS
    // ========================================================

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
      `Email: ${
        data?.email ||
        email
      }`
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


    // ========================================================
    // STUDENT REPORT
    // ========================================================

    if (
      reportRole === "student"
    ) {

      writeText(
        "Security Explanation",
        {
          fontSize: 14,
          bold: true,
        }
      );


      if (
        reportFindings.length === 0
      ) {

        writeText(
          "No security vulnerabilities were detected during the automated security scan."
        );

      } else {

        reportFindings.forEach(
          (
            finding,
            index
          ) => {

            const assessment =
              reportAssessments[
                index
              ] || {};


            writeText(
              `Vulnerability ${
                index + 1
              }: ${
                getVulnerabilityType(
                  finding,
                  assessment
                )
              }`,
              {
                fontSize: 12,
                bold: true,
              }
            );


            writeText(
              `Where: ${
                finding?.path ||
                "Unknown"
              } at line ${
                getLine(
                  finding
                )
              }`
            );


            writeText(
              `What was detected: ${
                getMessage(
                  finding
                )
              }`
            );


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


            writeText(
              "What the system did: The repository was scanned, findings were risk-assessed, and AI-generated corrected copies were prepared where possible."
            );


            y += 4;
          }
        );
      }

    } else {

      // ======================================================
      // DEVELOPER REPORT
      // ======================================================

      writeText(
        "Technical Security Findings",
        {
          fontSize: 14,
          bold: true,
        }
      );


      if (
        reportFindings.length === 0
      ) {

        writeText(
          "No security vulnerabilities were detected during the automated security scan."
        );

      } else {

        reportFindings.forEach(
          (
            finding,
            index
          ) => {

            const assessment =
              reportAssessments[
                index
              ] || {};


            writeText(
              `Finding ${
                index + 1
              }: ${
                getVulnerabilityType(
                  finding,
                  assessment
                )
              }`,
              {
                fontSize: 12,
                bold: true,
              }
            );


            writeText(
              `Semgrep Rule: ${
                finding?.check_id ||
                "Unknown"
              }`
            );


            writeText(
              `File: ${
                finding?.path ||
                "Unknown"
              }`
            );


            writeText(
              `Line: ${
                getLine(
                  finding
                )
              }`
            );


            writeText(
              `Severity: ${
                getSeverity(
                  finding,
                  assessment
                )
              }`
            );


            writeText(
              `CWE: ${
                getCwe(
                  finding,
                  assessment
                )
              }`
            );


            writeText(
              `Risk Score: ${
                getRiskScore(
                  assessment
                )
              }`
            );


            writeText(
              `Risk Level: ${
                getRiskLevel(
                  assessment
                )
              }`
            );


            writeText(
              `Semgrep Message: ${
                getMessage(
                  finding
                )
              }`
            );


            writeText(
              `Impact: ${
                assessment?.impact ||
                "Not specified"
              }`
            );


            writeText(
              `Exploitability: ${
                assessment?.exploitability ||
                "Not specified"
              }`
            );


            writeText(
              `Recommended Remediation: ${
                assessment?.recommendation ||
                "Not specified"
              }`
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


            y += 4;
          }
        );
      }
    }


    // ========================================================
    // AUTO-FIX SUMMARY
    // ========================================================

    writeText(
      "AI Auto-Fix Summary",
      {
        fontSize: 14,
        bold: true,
      }
    );


    const reportFixes =
      data?.fixes || [];


    const successfulFixes =
      reportFixes.filter(
        (fix) =>
          fix?.success
      ).length;


    const skippedFixes =
      reportFixes.filter(
        (fix) =>
          !fix?.success
      ).length;


    writeText(
      `Successful fixes generated: ${
        successfulFixes
      }`
    );


    writeText(
      `Skipped / failed fixes: ${
        skippedFixes
      }`
    );


    writeText(
      "The original uploaded repository was not modified. Corrected source files are prepared as a new repository ZIP."
    );


    writeText(
      "Validation note: Phase 4 does not perform a second security scan after AI Auto-Fix, so generated fixes are not claimed as security-verified."
    );


    // ========================================================
    // FINAL STATUS
    // ========================================================

    writeText(
      "System Status",
      {
        fontSize: 14,
        bold: true,
      }
    );


    writeText(
      "Automated repository scanning and risk assessment completed."
    );


    writeText(
      "AI was used for vulnerability remediation only."
    );


    writeText(
      "Report generation does not use the Groq API."
    );


    // ========================================================
    // FOOTER
    // ========================================================

    addPageIfNeeded(
      15
    );


    y += 5;


    doc.line(
      15,
      y,
      pageWidth - 15,
      y
    );


    y += 6;


    writeText(
      "Generated by the automated repository security analysis system.",
      {
        fontSize: 8,
      }
    );


    return doc;
  }


  // ==========================================================
  // MANUAL PDF DOWNLOAD
  // ==========================================================

  function downloadSecurityReport() {

    if (!scanData) {
      return;
    }


    try {

      setPdfStatus(
        "Generating security report..."
      );


      const doc =
        buildSecurityReportPDF(
          scanData
        );


      const repositoryName =
        scanData?.filename ||
        selectedFile?.name ||
        "repository.zip";


      const safeName =
        String(repositoryName)
          .replace(
            /\.zip$/i,
            ""
          )
          .replace(
            /[^\w.-]+/g,
            "_"
          );


      doc.save(
        `Security_Report_${safeName}.pdf`
      );


      setPdfDownloaded(
        true
      );


      setPdfStatus(
        "Security report downloaded successfully."
      );

    } catch (pdfError) {

      console.error(
        "PDF error:",
        pdfError
      );


      setPdfStatus(
        `PDF download failed: ${
          pdfError?.message ||
          "Unknown error"
        }`
      );
    }
  }


  // ==========================================================
  // MANUAL FIXED ZIP DOWNLOAD
  // ==========================================================

  async function downloadFixedRepository() {

    if (!selectedFile) {

      setZipStatus(
        "Original repository ZIP is unavailable."
      );

      return;
    }


    if (!scanData) {

      setZipStatus(
        "Analysis results are unavailable."
      );

      return;
    }


    try {

      setZipStatus(
        "Preparing fixed repository..."
      );


      // ------------------------------------------------------
      // LOAD ORIGINAL ZIP
      // ------------------------------------------------------

      const originalBuffer =
        await selectedFile.arrayBuffer();


      const zip =
        await JSZip.loadAsync(
          originalBuffer
        );


      const fixes =
        scanData?.fixes || [];


      let replacedCount = 0;

      let skippedCount = 0;


      // ------------------------------------------------------
      // APPLY FIXES
      // ------------------------------------------------------

      for (
        const fix of fixes
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


        // ----------------------------------------------------
        // EXACT MATCH
        // ----------------------------------------------------

        if (
          zip.file(
            targetPath
          )
        ) {

          zip.file(
            targetPath,
            fix.fixed_code
          );

          replacedCount += 1;

          continue;
        }


        // ----------------------------------------------------
        // ./ VARIANT
        // ----------------------------------------------------

        const dotPath =
          `./${targetPath}`;


        if (
          zip.file(
            dotPath
          )
        ) {

          zip.file(
            dotPath,
            fix.fixed_code
          );

          replacedCount += 1;

          continue;
        }


        // ----------------------------------------------------
        // NORMALIZED SEARCH
        // ----------------------------------------------------

        let matchedPath =
          null;


        zip.forEach(
          (
            relativePath
          ) => {

            if (
              matchedPath ||
              relativePath.endsWith("/")
            ) {
              return;
            }


            if (
              normalizePath(
                relativePath
              ) ===
              targetPath
            ) {

              matchedPath =
                relativePath;
            }
          }
        );


        if (matchedPath) {

          zip.file(
            matchedPath,
            fix.fixed_code
          );

          replacedCount += 1;

        } else {

          skippedCount += 1;
        }
      }


      // ------------------------------------------------------
      // ADD MANIFEST
      // ------------------------------------------------------

      const manifest = {

        project_title:
          PROJECT_TITLE,

        repository:
          scanData?.filename ||
          selectedFile.name,

        auto_fix_generated:
          fixes.length,

        files_replaced:
          replacedCount,

        files_not_replaced:
          skippedCount,

        original_repository_modified:
          false,

        second_security_scan:
          false,

        validation_status:
          scanData?.validation_status ||
          "Validation preparation completed.",
      };


      zip.file(
        "security-analysis-manifest.json",
        JSON.stringify(
          manifest,
          null,
          2
        )
      );


      // ------------------------------------------------------
      // BUILD ZIP
      // ------------------------------------------------------

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


      // ------------------------------------------------------
      // DOWNLOAD
      // ------------------------------------------------------

      const repositoryName =
        scanData?.filename ||
        selectedFile.name;


      const safeName =
        String(repositoryName)
          .replace(
            /\.zip$/i,
            ""
          )
          .replace(
            /[^\w.-]+/g,
            "_"
          );


      downloadBlob(
        outputBlob,
        `Fixed_Repository_${safeName}.zip`
      );


      setZipDownloaded(
        true
      );


      setZipStatus(
        `Fixed repository downloaded. ${replacedCount} file(s) replaced.`
      );

    } catch (zipError) {

      console.error(
        "ZIP generation error:",
        zipError
      );


      setZipStatus(
        `Fixed repository download failed: ${
          zipError?.message ||
          "Unknown error"
        }`
      );
    }
  }


  // ==========================================================
  // AUTOMATIC EMAIL
  // ==========================================================

  async function sendAutomaticEmail(
    data
  ) {

    if (
      !EMAILJS_SERVICE_ID ||
      !EMAILJS_TEMPLATE_ID ||
      !EMAILJS_PUBLIC_KEY
    ) {

      throw new Error(
        "EmailJS environment variables are not configured."
      );
    }


    const reportFindings =
      data?.findings || [];


    const reportAssessments =
      data?.risk_assessments || [];


    const reportFixes =
      data?.fixes || [];


    const reportRisk =
      data?.overall_risk || {};


    let findingsHtml =
      "";


    if (
      reportFindings.length === 0
    ) {

      findingsHtml =
        "<p>No security vulnerabilities were detected.</p>";

    } else {

      findingsHtml =
        reportFindings
          .map(
            (
              finding,
              index
            ) => {

              const assessment =
                reportAssessments[
                  index
                ] || {};


              return `
                <div style="
                  border:1px solid #e5e7eb;
                  border-radius:10px;
                  padding:15px;
                  margin-bottom:12px;
                  font-family:Arial,sans-serif;
                ">

                  <h3 style="margin-top:0;">
                    ${escapeHtml(
                      getVulnerabilityType(
                        finding,
                        assessment
                      )
                    )}
                  </h3>

                  <p>
                    <strong>Severity:</strong>
                    ${escapeHtml(
                      getSeverity(
                        finding,
                        assessment
                      )
                    )}
                  </p>

                  <p>
                    <strong>File:</strong>
                    ${escapeHtml(
                      finding?.path ||
                      "Unknown"
                    )}
                  </p>

                  <p>
                    <strong>Line:</strong>
                    ${escapeHtml(
                      getLine(
                        finding
                      )
                    )}
                  </p>

                  <p>
                    <strong>CWE:</strong>
                    ${escapeHtml(
                      getCwe(
                        finding,
                        assessment
                      )
                    )}
                  </p>

                  <p>
                    <strong>Risk:</strong>
                    ${escapeHtml(
                      getRiskScore(
                        assessment
                      )
                    )}
                  </p>

                  <p>
                    <strong>Recommendation:</strong>
                    ${escapeHtml(
                      assessment?.recommendation ||
                      "Not specified"
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
        (fix) =>
          fix?.success
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

      project_title:
        PROJECT_TITLE,

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

      validation_status:
        data?.validation_status ||
        "Validation preparation completed. No second security scan was performed.",

      subject:
        `Repository Security Report - ${
          data?.filename ||
          "Repository"
        }`,
    };


    await emailjs.send(
      EMAILJS_SERVICE_ID,
      EMAILJS_TEMPLATE_ID,
      templateParams,
      {
        publicKey:
          EMAILJS_PUBLIC_KEY,
      }
    );


    return true;
  }


  // ==========================================================
  // RUN AUTOMATIC EMAIL AFTER COMPLETION
  // ==========================================================

  async function triggerAutomaticEmail(
    data
  ) {

    try {

      setEmailStatus(
        "Sending security report to your email..."
      );


      await sendAutomaticEmail(
        data
      );


      setEmailStatus(
        `Security report sent successfully to ${
          data?.email ||
          email
        }.`
      );

    } catch (emailError) {

      console.error(
        "Email delivery error:",
        emailError
      );


      setEmailStatus(
        `Email delivery failed: ${
          emailError?.message ||
          "Unknown error"
        }`
      );
    }
  }


  // ==========================================================
  // EMAIL AFTER COMPLETION
  // ==========================================================

  async function handleCompletionEmail() {

    if (!scanData) {
      return;
    }


    if (
      emailStatus.startsWith(
        "Security report sent"
      )
    ) {
      return;
    }


    await triggerAutomaticEmail(
      scanData
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

    setProgressStage(-1);

    setProgressMessage("");

    setPdfDownloaded(false);

    setZipDownloaded(false);

    setEmailStatus("");

    setPdfStatus("");

    setZipStatus("");


    const input =
      document.getElementById(
        "repository-upload"
      );


    if (input) {
      input.value = "";
    }
  }


  // ==========================================================
  // AUTO EMAIL TRIGGER
  // ==========================================================

  if (
    completed &&
    scanData &&
    !emailStatus
  ) {

    void handleCompletionEmail();
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
            AI
          </div>

          <div className="brand-text">

            <h1>
              Security Analysis
            </h1>

            <p>
              Automated repository security platform
            </p>

          </div>

        </div>

      </header>


      {/* ================================================== */}
      {/* MAIN */}
      {/* ================================================== */}

      <main className="main-container">


        {/* ================================================== */}
        {/* INPUT SCREEN */}
        {/* ================================================== */}

        {!running &&
          !completed && (
            <>

              <section className="hero-section">

                <div className="hero-content">

                  <span className="hero-label">
                    SOFTWARE SECURITY
                  </span>

                  <h2>
                    {PROJECT_TITLE}
                  </h2>

                  <p>
                    Upload your repository and let
                    the system automatically detect
                    vulnerabilities, assess risk and
                    prepare AI-assisted security fixes.
                  </p>

                </div>

              </section>


              <section className="input-card">

                <div className="section-heading">

                  <div>

                    <span>
                      START ANALYSIS
                    </span>

                    <h3>
                      Repository Security Analysis
                    </h3>

                  </div>

                </div>


                {/* ROLE */}

                <div className="input-group">

                  <label>
                    Select your role
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
                  />

                </div>


                {/* ZIP */}

                <div className="input-group">

                  <label>
                    Repository ZIP
                  </label>


                  <label
                    htmlFor="repository-upload"
                    className="upload-box"
                  >

                    <input
                      id="repository-upload"
                      type="file"
                      accept=".zip,application/zip"
                      onChange={
                        handleFileChange
                      }
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


                {/* START BUTTON */}

                <button
                  type="button"
                  className="start-button"
                  onClick={
                    startAutonomousAnalysis
                  }
                >

                  Start Autonomous Analysis

                  <span>
                    →
                  </span>

                </button>

              </section>

            </>
          )}


        {/* ================================================== */}
        {/* RUNNING SCREEN */}
        {/* ================================================== */}

        {running && (

          <section className="progress-page">

            <div className="progress-card">

              <span className="hero-label">
                AUTONOMOUS ANALYSIS
              </span>

              <h2>
                Securing your repository...
              </h2>

              <p>
                The system is processing your
                repository. Each stage will complete
                automatically.
              </p>


              {/* PROGRESS BAR */}

              <div className="progress-bar">

                <div
                  className="progress-fill"
                  style={{
                    width: `${
                      Math.max(
                        8,
                        ((progressStage + 1) /
                          PIPELINE_STAGES.length) *
                          100
                      )
                    }%`,
                  }}
                />

              </div>


              {/* CURRENT MESSAGE */}

              <div className="progress-current">

                <span className="progress-spinner" />

                <span>
                  {progressMessage ||
                    "Starting analysis..."}
                </span>

              </div>


              {/* STAGES */}

              <div className="progress-list">

                {PIPELINE_STAGES.map(
                  (
                    stage,
                    index
                  ) => {

                    let state =
                      "pending";


                    if (
                      index <
                      progressStage
                    ) {

                      state =
                        "completed";

                    } else if (
                      index ===
                      progressStage
                    ) {

                      state =
                        "active";
                    }


                    return (
                      <div
                        className={
                          `progress-stage ${state}`
                        }
                        key={
                          stage.id
                        }
                      >

                        <div className="progress-stage-icon">

                          {state ===
                            "completed" && (
                            <span>
                              ✓
                            </span>
                          )}

                          {state ===
                            "active" && (
                            <span className="mini-spinner" />
                          )}

                          {state ===
                            "pending" && (
                            <span>
                              {index + 1}
                            </span>
                          )}

                        </div>


                        <div>

                          <strong>
                            {stage.title}
                          </strong>

                          {state ===
                            "active" && (
                            <small>
                              Processing...
                            </small>
                          )}

                        </div>

                      </div>
                    );
                  }
                )}

              </div>

            </div>

          </section>
        )}


        {/* ================================================== */}
        {/* RESULTS */}
        {/* ================================================== */}

        {completed &&
          scanData && (

            <section className="results-section">


              {/* RESULT HEADER */}

              <div className="results-header">

                <div>

                  <span className="hero-label">
                    ANALYSIS COMPLETED
                  </span>

                  <h2>
                    Security results are ready.
                  </h2>

                  <p>
                    {
                      scanData.filename
                    }
                  </p>

                </div>


                <button
                  type="button"
                  className="secondary-button"
                  onClick={
                    resetAnalysis
                  }
                >
                  New Analysis
                </button>

              </div>


              {/* PROJECT TITLE */}

              <div className="results-card">

                <div className="project-title-box">

                  <span>
                    PROJECT
                  </span>

                  <strong>
                    {PROJECT_TITLE}
                  </strong>

                </div>

              </div>


              {/* PIPELINE */}

              <div className="results-card">

                <div className="section-heading">

                  <div>

                    <span>
                      PROCESS
                    </span>

                    <h3>
                      Completed workflow
                    </h3>

                  </div>

                </div>


                <div className="pipeline-list">

                  {(
                    scanData?.stages ||
                    []
                  ).map(
                    (
                      stage,
                      index
                    ) => (

                      <div
                        className={
                          `pipeline-item ${
                            stage.status
                          }`
                        }
                        key={
                          stage.id ||
                          index
                        }
                      >

                        <div className="pipeline-icon">

                          {stage.status ===
                            "completed" && (
                            <span>
                              ✓
                            </span>
                          )}

                          {stage.status ===
                            "skipped" && (
                            <span>
                              –
                            </span>
                          )}

                          {stage.status ===
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
                          {stage.status}
                        </div>

                      </div>
                    )
                  )}

                </div>

              </div>


              {/* STATS */}

              <div className="stats-grid">

                <div className="stat-card">

                  <span>
                    FINDINGS
                  </span>

                  <strong>
                    {
                      scanData.findings?.length ||
                      0
                    }
                  </strong>

                </div>


                <div className="stat-card">

                  <span>
                    RISK SCORE
                  </span>

                  <strong>
                    {
                      scanData.overall_risk?.score ??
                      scanData.overall_risk?.overall_score ??
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
                      scanData.overall_risk?.risk_level ??
                      scanData.overall_risk?.level ??
                      "N/A"
                    }
                  </strong>

                </div>


                <div className="stat-card">

                  <span>
                    AI FIXES
                  </span>

                  <strong>
                    {
                      scanData.fixes?.filter(
                        (fix) =>
                          fix?.success
                      ).length || 0
                    }
                  </strong>

                </div>

              </div>


              {/* FINDINGS */}

              <div className="results-card">

                <div className="section-heading">

                  <div>

                    <span>
                      SECURITY FINDINGS
                    </span>

                    <h3>
                      Vulnerabilities detected
                    </h3>

                  </div>

                </div>


                {scanData.findings?.length ===
                0 ? (

                  <div className="secure-box">
                    ✓ No security vulnerabilities
                    were detected.
                  </div>

                ) : (

                  <div className="finding-list">

                    {scanData.findings.map(
                      (
                        finding,
                        index
                      ) => {

                        const assessment =
                          scanData.risk_assessments?.[
                            index
                          ] || {};


                        return (
                          <article
                            className="finding-card"
                            key={
                              index
                            }
                          >

                            <div className="finding-header">

                              <div>

                                <span className="finding-number">
                                  FINDING {
                                    index + 1
                                  }
                                </span>

                                <h4>
                                  {
                                    getVulnerabilityType(
                                      finding,
                                      assessment
                                    )
                                  }
                                </h4>

                              </div>


                              <span className="severity-badge">
                                {
                                  getSeverity(
                                    finding,
                                    assessment
                                  )
                                }
                              </span>

                            </div>


                            <div className="finding-meta">

                              <div>

                                <span>
                                  File
                                </span>

                                <strong>
                                  {
                                    finding?.path ||
                                    "Unknown"
                                  }
                                </strong>

                              </div>


                              <div>

                                <span>
                                  Line
                                </span>

                                <strong>
                                  {
                                    getLine(
                                      finding
                                    )
                                  }
                                </strong>

                              </div>


                              <div>

                                <span>
                                  CWE
                                </span>

                                <strong>
                                  {
                                    getCwe(
                                      finding,
                                      assessment
                                    )
                                  }
                                </strong>

                              </div>


                              <div>

                                <span>
                                  Risk
                                </span>

                                <strong>
                                  {
                                    getRiskScore(
                                      assessment
                                    )
                                  }
                                </strong>

                              </div>

                            </div>


                            <div className="finding-message">

                              <span>
                                Semgrep Message
                              </span>

                              <p>
                                {
                                  getMessage(
                                    finding
                                  )
                                }
                              </p>

                            </div>


                            {finding?.source_code && (

                              <details className="source-details">

                                <summary>
                                  View source context
                                </summary>

                                <pre>
                                  {
                                    finding.source_code
                                  }
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


              {/* AUTO-FIX */}

              <div className="results-card">

                <div className="section-heading">

                  <div>

                    <span>
                      AI AUTO-FIX
                    </span>

                    <h3>
                      Remediation results
                    </h3>

                  </div>

                </div>


                <div className="fix-summary">

                  <div>

                    <strong>
                      {
                        scanData.fixes?.filter(
                          (fix) =>
                            fix?.success
                        ).length || 0
                      }
                    </strong>

                    <span>
                      fixes generated
                    </span>

                  </div>


                  <div>

                    <strong>
                      {
                        scanData.fixes?.filter(
                          (fix) =>
                            !fix?.success
                        ).length || 0
                      }
                    </strong>

                    <span>
                      skipped / unavailable
                    </span>

                  </div>

                </div>


                <div className="note-box">

                  Groq AI was used only for
                  Auto-Fix generation. The original
                  repository remains unchanged.

                </div>


                <div className="note-box">

                  No second security scan was
                  performed after Auto-Fix generation.
                  Therefore generated fixes are not
                  claimed as security-verified.

                </div>

              </div>


              {/* DOWNLOADS */}

              <div className="results-card">

                <div className="section-heading">

                  <div>

                    <span>
                      DOWNLOADS
                    </span>

                    <h3>
                      Get your generated files
                    </h3>

                  </div>

                </div>


                <div className="download-grid">


                  {/* PDF */}

                  <div className="download-card">

                    <div className="download-icon">
                      PDF
                    </div>

                    <div>

                      <strong>
                        Security Report
                      </strong>

                      <small>
                        Role-based vulnerability report
                      </small>

                    </div>


                    <button
                      type="button"
                      className="download-button"
                      onClick={
                        downloadSecurityReport
                      }
                    >
                      Download Report
                    </button>


                    {pdfStatus && (
                      <p className="delivery-status">
                        {pdfStatus}
                      </p>
                    )}

                  </div>


                  {/* ZIP */}

                  <div className="download-card">

                    <div className="download-icon">
                      ZIP
                    </div>

                    <div>

                      <strong>
                        Fixed Repository
                      </strong>

                      <small>
                        Original files + generated fixes
                      </small>

                    </div>


                    <button
                      type="button"
                      className="download-button"
                      onClick={
                        downloadFixedRepository
                      }
                    >
                      Download Fixed ZIP
                    </button>


                    {zipStatus && (
                      <p className="delivery-status">
                        {zipStatus}
                      </p>
                    )}

                  </div>

                </div>

              </div>


              {/* EMAIL */}

              <div className="results-card">

                <div className="section-heading">

                  <div>

                    <span>
                      EMAIL
                    </span>

                    <h3>
                      Report delivery
                    </h3>

                  </div>

                </div>


                <div className="email-status-card">

                  <div className="email-status-icon">
                    ✉
                  </div>

                  <div>

                    <strong>
                      Automatic email delivery
                    </strong>

                    <small>
                      {
                        emailStatus ||
                        "Preparing email report..."
                      }
                    </small>

                  </div>

                </div>

              </div>


              {/* VALIDATION */}

              <div className="validation-banner">

                <strong>
                  Validation Status
                </strong>

                <p>
                  {
                    scanData.validation_status ||
                    "Validation preparation completed. No second security scan was performed."
                  }
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
          {PROJECT_TITLE}
        </span>

        <span>
          Automated Security Analysis
        </span>

      </footer>

    </div>
  );
}