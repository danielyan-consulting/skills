# Report Template for OWASP Top 10:2025 Security Review

Follow this structure exactly when assembling the final report. Replace all placeholders
(shown in curly braces) with actual values.

---

## Report Structure

```markdown
# OWASP Top 10:2025 Security Review Report

**Project:** {project name, derived from codebase root directory name}
**Review Date:** {current date}
**Reviewer:** Automated OWASP Top 10:2025 Security Review
**Codebase Root:** `{codebase root path}`
**Languages:** {detected languages}
**Frameworks:** {detected frameworks}

---

## Executive Summary

This report presents the findings of a security review of the {project name} codebase,
assessed against all 10 categories of the OWASP Top 10:2025 standard.

**Overall Risk Assessment:** {CRITICAL / HIGH / MEDIUM / LOW}

Derive the overall risk from the highest severity finding across all categories. If there
are no findings at all, the overall risk is LOW.

| Severity | Count |
|----------|-------|
| Critical | {n} |
| High | {n} |
| Medium | {n} |
| Low | {n} |
| Informational | {n} |
| **Total** | **{n}** |

{Write 2-3 paragraphs summarising:
- Total number of findings and the overall security posture
- Which categories had the most/most severe findings
- Which categories had no findings
- The most urgent issues requiring immediate attention
- Note that absence of findings does not guarantee absence of vulnerabilities}

---

## Scope and Methodology

### Scope
- **Files reviewed:** {n} files across {n} directories
- **Languages:** {languages}
- **Frameworks:** {frameworks}
- **Application type:** {API-only / SPA+backend / server-rendered / etc.}

### Methodology
This review employed 10 specialist analysis passes, each focused on one OWASP Top 10:2025
category. Each pass reviewed the subset of source files most relevant to its category and
performed a code-level review focused on identifying weaknesses, assessing severity, and
proposing context-sensitive remediations.

### Limitations
- This is a static code review. Runtime behaviour, deployed configuration, and
  infrastructure-level controls were not assessed.
- Only the source code provided was reviewed. External services, APIs, and third-party
  integrations were not tested.
- Absence of findings does not guarantee absence of vulnerabilities.
- Dynamic testing (DAST), penetration testing, and threat modelling are recommended as
  complementary activities.

### Secrets Handling
Any secrets, passwords, API keys, tokens, or credentials discovered during this review
have been flagged as findings but their actual values have been replaced with `REDACTED`
throughout this report to prevent inadvertent disclosure.

---

## Risk Summary Dashboard

| Category | Critical | High | Medium | Low | Info | Status |
|----------|----------|------|--------|-----|------|--------|
| A01 -- Broken Access Control | {n} | {n} | {n} | {n} | {n} | {PASS/WARN/FAIL} |
| A02 -- Security Misconfiguration | {n} | {n} | {n} | {n} | {n} | {PASS/WARN/FAIL} |
| A03 -- Software Supply Chain Failures | {n} | {n} | {n} | {n} | {n} | {PASS/WARN/FAIL} |
| A04 -- Cryptographic Failures | {n} | {n} | {n} | {n} | {n} | {PASS/WARN/FAIL} |
| A05 -- Injection | {n} | {n} | {n} | {n} | {n} | {PASS/WARN/FAIL} |
| A06 -- Insecure Design | {n} | {n} | {n} | {n} | {n} | {PASS/WARN/FAIL} |
| A07 -- Authentication Failures | {n} | {n} | {n} | {n} | {n} | {PASS/WARN/FAIL} |
| A08 -- Integrity Failures | {n} | {n} | {n} | {n} | {n} | {PASS/WARN/FAIL} |
| A09 -- Logging and Alerting Failures | {n} | {n} | {n} | {n} | {n} | {PASS/WARN/FAIL} |
| A10 -- Exceptional Conditions | {n} | {n} | {n} | {n} | {n} | {PASS/WARN/FAIL} |

Status key:
- **FAIL** = any Critical or High severity findings
- **WARN** = Medium severity findings only (no Critical or High)
- **PASS** = Low/Informational only, or no findings

---

## Detailed Findings by Category

{For each of the 10 categories, include a section. If the category has findings, list them
sorted by severity (Critical first, then High, Medium, Low, Informational). If a category
has no findings, include the "no issues" note below.}

### A01:2025 -- Broken Access Control

{If findings exist:}

**Findings:** {count} | **Highest Severity:** {highest}

{List each finding using the standard finding format from agent_prompts.md}

{If no findings:}

**Findings:** 0 | **Status:** PASS

No issues were identified for this category. This does not guarantee the absence of
vulnerabilities; complementary dynamic testing is recommended.

{Repeat for A02 through A10}

---

## Remediation Priority Matrix

### Immediate Action Required (Critical and High)

{List all Critical and High findings as bullet points:}
- **{ID}** [{SEVERITY}]: {title} (`{file}`)

{If none: "No Critical or High severity findings."}

### Short-Term Remediation (Medium)

{List all Medium findings as bullet points}

{If none: "No Medium severity findings."}

### Hardening Recommendations (Low and Informational)

{List all Low and Informational findings as bullet points}

{If none: "No Low or Informational findings."}

---

## Appendix A: Files Reviewed

{List all files that were read during the review, grouped by directory}

## Appendix B: Standards and References

- **Standard:** OWASP Top 10:2025 (https://owasp.org/Top10/2025/)
- **Methodology:** 10-category specialist code review with structured findings
- **Severity Scale:** CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL (aligned with CVSS concepts)
```
