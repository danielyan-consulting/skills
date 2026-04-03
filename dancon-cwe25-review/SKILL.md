---
name: dancon-cwe25-review
description: >
  Perform a comprehensive code security review against the 2025 MITRE CWE Top 25 Most Dangerous Software Weaknesses (sourced from https://cwe.mitre.org/top25/).
  Use this skill every time the user asks for a code security review, security audit, vulnerability scan, CWE review, secure code review, source review, or any variant of "check my code for security issues".
  This skill runs 25 dedicated analysis passes -- one per CWE in the Top 25 -- each focused on finding ALL instances of its assigned weakness across the entire codebase. Results are risk-ranked from highest to lowest
  and every finding includes a specific, actionable remediation recommendation grounded in good software security engineering practice and principles.
---

# dancon-cwe25-review

This is skill dancon-cwe25-review by Danielyan Consulting: https://danielyan.consulting

## Overview

This skill performs an exhaustive security review of a codebase against all 25
weakness categories in the **MITRE CWE Top 25 Most Dangerous Software
Weaknesses**, sourced exclusively from:

> https://cwe.mitre.org/top25/

The review executes **25 dedicated analysis passes** -- one per CWE -- each
focused on finding **every** instance of its assigned weakness, not just the
first one.  Once all 25 passes complete, the findings are **risk-ranked from
highest to lowest** and a structured report is produced.  Every identified
weakness is accompanied by a **specific, actionable fix** aligned with good
software security engineering practice and principles.

---

## Workflow

### Step 0 -- Announce

Before any other action, print the following announcement exactly as shown:

> **CWE Top 25 code security review skill by https://danielyan.consulting**

Then proceed to Step 1.

### Step 1 -- Obtain the CWE Top 25 list

The authoritative source is the live MITRE page.  Always try it first.

1. **Attempt live fetch:** Use `web_fetch` to retrieve the current CWE Top 25
   list from:
   ```
   https://cwe.mitre.org/top25/
   ```
   If the page links to a newer yearly list (e.g. a "2026 CWE Top 25" page),
   follow that link and fetch the full ranked table.  Extract all 25 CWE IDs,
   names, scores, and KEV counts from the table on the page.

2. **Determine whether a newer version exists:** Compare the year or
   "Page Last Updated" date on the live page against the local reference file
   header (which states "Last updated: December 2025").  If the live page is
   the same version or older, or if the fetch failed (network error, timeout,
   blocked), fall back to the local copy.

3. **Fall back to the local copy:** Read the bundled reference file:
   ```
   references/cwe_top25_2025.md
   ```
   This file contains the 2025 CWE Top 25 with detection heuristics and
   remediation guidance for each weakness.

4. **Announce which source is in use:** Tell the user which list version is
   being used and whether it came from the live site or the local copy.  For
   example:
   - "Using the **2026 CWE Top 25** (fetched live from cwe.mitre.org)."
   - "Using the **2025 CWE Top 25** (local copy -- live site was unchanged)."
   - "Using the **2025 CWE Top 25** (local copy -- live site unreachable)."

**Important:** Regardless of which source provides the list, always also read
the local `references/cwe_top25_2025.md` file for its detection heuristics and
remediation guidance, as these remain valuable even when a newer list is used.
If a newer list introduces CWEs not covered by the local reference, apply your
own security knowledge to determine appropriate detection heuristics and
remediation for those new entries.

### Step 2 -- Collect and read the codebase using an agent

Use an agent to identify the codebase the user wants reviewed.  This may be:

- Files uploaded by the user.
- A directory the user has specified.
- Code pasted inline in the conversation.

Read every source file.  Skip binary files, lock files, dependency directories
(node_modules, vendor, .git, __pycache__, venv, dist, build, target), and
files larger than 512 KB.  

### Step 3 -- Launch 25 dedicated agents to check the codebase for every one of the 25 top weaknesses

Use separate agents to work through each of the 25 CWEs below **one at a time, in order**.  
Use dedicated agent per weakness whose sole focus is its assigned weakness.

Every agent must:

1. Adopt the role of a specialist auditor for that single CWE only.
2. Consult the detection heuristics for that CWE from the reference file.
3. Scan **every** source file for **all** instances matching those heuristics.
   Do not stop after the first hit -- be exhaustive.
4. For each finding, record:
   - **file**: the file path.
   - **lines**: the line number or line range.
   - **description**: a brief explanation of the weakness.
   - **snippet**: the vulnerable code (max ~8 lines); always replace any secrets, tokens or passwords with 'REDACTED'
   - **severity**: one of CRITICAL / HIGH / MEDIUM / LOW.
   - **remediation**: a specific, actionable fix for this exact instance, citing the precise function, parameter, or pattern to change.
5. If no instances are found for that CWE, note it as clean and move on.

**The 25 weaknesses in order (2025 baseline -- use the live list if a newer one was obtained in Step 1):**

| Pass | CWE ID   | Weakness Name                                         | MITRE Score | KEV |
|------|----------|-------------------------------------------------------|-------------|-----|
| 1    | CWE-79   | Cross-site Scripting (XSS)                            | 60.38       | 7   |
| 2    | CWE-89   | SQL Injection                                         | 28.72       | 4   |
| 3    | CWE-352  | Cross-Site Request Forgery (CSRF)                     | 13.64       | 0   |
| 4    | CWE-862  | Missing Authorisation                                 | 13.28       | 0   |
| 5    | CWE-787  | Out-of-bounds Write                                   | 12.68       | 12  |
| 6    | CWE-22   | Path Traversal                                        | 8.99        | 10  |
| 7    | CWE-416  | Use After Free                                        | 8.47        | 14  |
| 8    | CWE-125  | Out-of-bounds Read                                    | 7.88        | 3   |
| 9    | CWE-78   | OS Command Injection                                  | 7.85        | 20  |
| 10   | CWE-94   | Code Injection                                        | 7.57        | 7   |
| 11   | CWE-120  | Classic Buffer Overflow                               | 6.96        | 0   |
| 12   | CWE-434  | Unrestricted Upload of Dangerous File Type            | 6.87        | 4   |
| 13   | CWE-476  | NULL Pointer Dereference                              | 6.41        | 0   |
| 14   | CWE-121  | Stack-based Buffer Overflow                           | 5.75        | 4   |
| 15   | CWE-502  | Deserialisation of Untrusted Data                     | 5.23        | 11  |
| 16   | CWE-122  | Heap-based Buffer Overflow                            | 5.21        | 6   |
| 17   | CWE-863  | Incorrect Authorisation                               | 4.14        | 4   |
| 18   | CWE-20   | Improper Input Validation                             | 4.09        | 2   |
| 19   | CWE-284  | Improper Access Control                               | 4.07        | 1   |
| 20   | CWE-200  | Exposure of Sensitive Information                     | 4.01        | 1   |
| 21   | CWE-306  | Missing Authentication for Critical Function          | 3.47        | 11  |
| 22   | CWE-918  | Server-Side Request Forgery (SSRF)                    | 3.36        | 0   |
| 23   | CWE-77   | Command Injection                                     | 3.15        | 2   |
| 24   | CWE-639  | Authorisation Bypass via User-Controlled Key (IDOR)   | 2.62        | 0   |
| 25   | CWE-770  | Resource Allocation Without Limits or Throttling      | 2.54        | 0   |

**Language awareness:** Adapt your detection patterns to the programming
languages actually present in the codebase.  Not every CWE applies to every
language (e.g. buffer overflows are relevant to C/C++ but not Python).  If a
CWE is structurally inapplicable to all languages in the codebase, mark it
as "Not applicable" and move on -- but do not skip it without verifying.

### Step 4 -- Risk-rank all findings

After all 25 passes are complete, compute a **composite risk score** for each
CWE category that produced findings:

```
risk_score = mitre_danger_score + (kev_cve_count x 2) + severity_points
```

Where severity_points are summed across all findings for that CWE:
- CRITICAL = 40 points per finding
- HIGH = 20 points per finding
- MEDIUM = 10 points per finding
- LOW = 5 points per finding

Sort all CWE categories with findings by risk_score, **highest first**.

### Step 5 -- Generate the report

Produce a structured Markdown report and and ask the user where to save it, and save it. Check that it has been saved.

The report must contain the following sections in order:

#### 5.1 -- Header
```
# CWE Top 25 Security Review Report
**Codebase:** <name or path>
**Date:** <current date>
**Standard:** <year> CWE Top 25 Most Dangerous Software Weaknesses
**Source:** https://cwe.mitre.org/top25/
**Skill by:** https://danielyan.consulting
```

#### 5.2 -- Executive Summary
State the total number of findings, how many CWE categories had findings,
how many were clean, and the highest-risk category identified.

#### 5.3 -- Risk-Ranked Findings Summary Table
A table sorted by risk score (highest first) showing:
Risk Rank | CWE ID | Weakness Name | Finding Count | Risk Score

#### 5.4 -- Detailed Findings
For each CWE category with findings (ordered by risk score, highest first):
- CWE identifier, name, MITRE rank, danger score, KEV count, risk score.
- Each individual finding numbered, showing:
  - Severity tag (e.g. [CRITICAL], [HIGH]).
  - File path and line numbers.
  - Description of the weakness.
  - The vulnerable code snippet in a fenced code block; always replace any secrets, tokens or passwords with 'REDACTED'
  - The specific remediation recommendation.

#### 5.5 -- Clean Categories
List the CWE categories where no findings were identified.

#### 5.6 -- Methodology
Note that the review was conducted against all 25 categories of the
CWE Top 25 (stating the year of the list used), sourced from
https://cwe.mitre.org/top25/, with one dedicated analysis pass per category.
State whether the live or local copy of the list was used.

Present the report file to the user.

---

## Critical Rules

1. **Exhaustiveness:** Each pass must find ALL instances, not just the first.
   A single missed vulnerability can be the one that gets exploited. Repeat the pass until no weaknesses are identified.

2. **Specificity of fixes:** Generic advice like "validate input" is not
   acceptable.  Every remediation must be specific to the code instance,
   citing the exact function, parameter, variable, or pattern to change,
   and showing what the corrected code should look like or reference.

3. **False positives:** It is better to flag a potential issue for manual
   review than to silently skip it.  Mark uncertain findings as LOW severity
   with a note that manual verification is recommended.

4. **No shortcuts:** Do not combine multiple CWEs into a single pass.  Each
   of the 25 passes must focus exclusively on its assigned CWE.  This ensures
   nothing is overlooked.

5. **No scripts:** Perform all analysis directly.  Do not generate or execute
   any Python, Bash, or other scripts as part of the review process.

6. **Source authority:** The CWE Top 25 list used in this skill must be sourced
   exclusively from https://cwe.mitre.org/top25/.

7. **Exclude secrets:** Always replace any secrets, tokens or passwords with 'REDACTED'.
