---
name: dancon-owasp10-review
description: >
  Parallel OWASP Top 10:2025 security review of a web application codebase using 10 specialist
  agents. Trigger whenever the user asks for a security review, security audit, OWASP review,
  vulnerability assessment, code security scan, or threat analysis of a web app codebase. Also
  trigger on mentions of "OWASP Top 10", "security vulnerabilities", "code audit", "AppSec",
  or requests to check code for injection, XSS, access control, auth, or crypto issues. Trigger
  for casual requests like "is my code secure?", "check for vulnerabilities", or "any security
  issues?". Launches 10 parallel agents (one per OWASP category) producing a report with
  context-sensitive remediations. Secrets found are flagged but always shown as REDACTED.
---

# OWASP Top 10:2025 Security Review

This is skill dancon-owasp10-review by Danielyan Consulting: https://danielyan.consulting

Review a web application codebase against all 10 categories of the OWASP Top 10:2025 standard,
using 10 specialist agents running in parallel. Each agent focuses on exactly one category,
produces structured findings, and proposes remediations tailored to the codebase's language and
framework. The results are aggregated into a single Markdown report.

---

## CRITICAL SAFETY RULE -- SECRETS HANDLING

This rule is absolute, non-negotiable, and applies at every stage of the review:

**Any secrets, passwords, API keys, tokens, private keys, connection strings, or credentials
discovered in the codebase MUST be flagged as findings but MUST NEVER be displayed in any
output. Always replace the actual value with `REDACTED`.**

Examples:
- `password = "REDACTED"`
- `API_KEY = "REDACTED"`
- `postgres://user:REDACTED@host/db`
- `Authorization: Bearer REDACTED`
- `-----BEGIN PRIVATE KEY----- REDACTED -----END PRIVATE KEY-----`
- Any string that looks like a token, hash, or secret embedded in source code

When copying code into evidence fields, visually scan for anything that could be a secret and
replace it before writing it into the finding. When in doubt, redact.

---

## OWASP Top 10:2025 Categories

These are the 10 categories. Each agent handles exactly one:

| # | ID | Category | Key Focus Areas |
|---|-----|----------|-----------------|
| 1 | A01:2025 | Broken Access Control | IDOR, missing authz, path traversal, CORS misconfig, SSRF, privilege escalation |
| 2 | A02:2025 | Security Misconfiguration | Default creds, debug mode, missing headers, verbose errors, open ports |
| 3 | A03:2025 | Software Supply Chain Failures | Vulnerable deps, unpinned versions, missing lock files, unverified integrity |
| 4 | A04:2025 | Cryptographic Failures | Weak algorithms, plaintext secrets, missing TLS, poor key management, weak hashing |
| 5 | A05:2025 | Injection | SQLi, XSS, command injection, SSTI, XXE, NoSQL injection, log injection |
| 6 | A06:2025 | Insecure Design | Missing threat modelling, no rate limiting, business logic flaws, no re-auth |
| 7 | A07:2025 | Identification and Authentication Failures | Weak passwords, broken sessions, missing MFA, credential stuffing, enumeration |
| 8 | A08:2025 | Software and Data Integrity Failures | Insecure deserialisation, unsigned updates, missing SRI, CI/CD trust issues |
| 9 | A09:2025 | Security Logging and Alerting Failures | Missing audit logs, no alerting, sensitive data in logs, log injection |
| 10 | A10:2025 | Mishandling of Exceptional Conditions | Fail-open logic, stack trace leakage, unhandled exceptions, TOCTOU |

---

## Workflow

### Step 1: Discover the codebase

Before reviewing anything, understand what you are looking at.

1. Locate the codebase root. This is typically:
   - A directory the user points to
   - An uploaded archive (extract it first with `tar` or `unzip`)

2. List the file tree (2 levels deep) using the `view` tool on the root directory.

3. Identify:
   - **Languages** used (from file extensions: .py, .js, .ts, .java, .go, .rb, .php, etc.)
   - **Frameworks** (look at package.json for Express/React/Next, requirements.txt for
     Django/Flask/FastAPI, Gemfile for Rails, go.mod for Gin/Fiber, pom.xml for Spring, etc.)
   - **Application type** (API-only, server-rendered, SPA with backend, etc.)

4. Build a mental map of which files are relevant to which OWASP category. Use these heuristics:

   | Category | Look at these files/directories |
   |----------|-------------------------------|
   | A01 | routes, controllers, middleware, auth, CORS config, guards, policies |
   | A02 | config files, .env, Dockerfile, docker-compose, nginx.conf, cloud templates |
   | A03 | package.json, requirements.txt, Gemfile, go.mod, lock files, CI/CD configs |
   | A04 | crypto modules, password hashing, TLS config, key files, cookie settings |
   | A05 | DB queries, template rendering, command execution, input handlers, search |
   | A06 | business logic, rate limiting, workflows, registration/payment flows |
   | A07 | login/logout, session config, OAuth/OIDC, JWT, password reset, MFA code |
   | A08 | deserialisation code, CI/CD configs, build scripts, CDN resource loading |
   | A09 | logging config, error handlers, audit trails, monitoring setup |
   | A10 | try/catch blocks, error middleware, fallback logic, timeout/retry config |

   When in doubt, include the file. Over-inclusion is better than missing a vulnerability.

### Step 2: Run the 10 category reviews

Read `references/agent_prompts.md` for the detailed instructions per category.

**If you have subagent capability (Claude Code, Cowork):**

Spawn all 10 agents in parallel in a single turn. Each agent receives:
- Its category-specific prompt from `references/agent_prompts.md`
- The technology context (languages, frameworks, app type) from Step 1
- The relevant source files for its category
- The secrets-handling rule

Each agent must return its findings as structured text following the finding format
described in the agent prompts reference.

**If you do not have subagents:**

Perform all 10 reviews yourself, sequentially, in one pass through the codebase. For each
category:
1. Read the category-specific instructions from `references/agent_prompts.md`
2. Read each relevant file using the `view` tool
3. Analyse the code for weaknesses in that category
4. Record your findings in the standard format
5. Move to the next category

To keep things efficient, you can batch-read files that are relevant to multiple
categories and note findings for all applicable categories as you go, rather than re-reading
files 10 times. Always ensure you find all instances of weaknesses, not just the first one.

### Step 3: Assemble findings

For each of the 10 categories, compile findings using this format per finding:

```
### [FINDING_ID]: [TITLE]

| Field | Detail |
|-------|--------|
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL |
| **File** | `path/to/file.js` |
| **Lines** | 42-58 |
| **CWE** | CWE-862 |

**Description:** [What the weakness is and why it matters]

**Evidence:**
```[language]
[Code snippet with any secrets REDACTED]
```

**Impact:** [What an attacker could achieve]

**Remediation:** [Specific, actionable fix for this codebase's stack]

**Recommended Fix:**
```[language]
[Code showing the remediated version]
```
```

### Step 4: Generate the report

Assemble the full report using the template in `references/report_template.md`. The report
structure is:

1. **Header** with project name, date, languages, frameworks
2. **Executive Summary** with overall risk rating and severity totals
3. **Scope and Methodology** including limitations and secrets-handling note
4. **Risk Summary Dashboard** -- a table with all 10 categories showing finding counts
   and PASS/WARN/FAIL status
5. **Detailed Findings by Category** -- all 10 categories, each with its findings or a
   "no issues identified" note
6. **Remediation Priority Matrix** -- findings grouped by urgency (Critical/High first,
   then Medium, then Low/Informational)
7. **Appendix** -- files reviewed and standards referenced

Write the report as a Markdown file and save it.
Present it to the user using the `present_files` tool.


## Severity Classification

Apply this scale consistently across all 10 categories:

| Severity | Criteria |
|----------|----------|
| CRITICAL | Actively exploitable with low effort; leads to full system compromise, data breach, or remote code execution. Requires immediate action. |
| HIGH | Exploitable with moderate effort; leads to significant data exposure, privilege escalation, or account takeover. Address urgently. |
| MEDIUM | Requires specific conditions to exploit; limited blast radius or partial data exposure. Address in the short term. |
| LOW | Minor issue or defence-in-depth concern; requires unlikely conditions or attacker-favourable circumstances. Address as part of regular hardening. |
| INFORMATIONAL | Best practice recommendation with no direct exploitability. Consider during next refactoring cycle. |

**Status derivation for the dashboard:**
- **FAIL** = any Critical or High findings in the category
- **WARN** = Medium findings only (no Critical or High)
- **PASS** = Low/Informational only, or no findings

---

## Guiding Principles

These principles apply to every finding and remediation you produce:

1. **Context-sensitive remediations.** Never give generic advice. If the app uses Express.js,
   show Express middleware. If it uses Django, show Django decorators. Match the language,
   framework, and idioms of the codebase.

2. **Evidence-based findings only.** Every finding must cite a specific file and line range.
   No speculative or hypothetical findings. If you cannot point to the code, do not report it.

3. **Defence in depth.** Where applicable, suggest layered mitigations rather than a single
   fix. For example, for injection: parameterised queries AND input validation AND output
   encoding.

4. **Least privilege.** Recommendations should always favour minimal permissions, scoped
   tokens, and restricted access.

5. **Secure defaults.** Prefer secure-by-default configurations. Flag anything that requires
   the developer to opt into security rather than opt out of it.

6. **No false confidence.** If a category has zero findings, state clearly that absence of
   findings does not guarantee absence of vulnerabilities. Static review has inherent
   limitations.

7. **Redact all secrets.** Repeat: never show a real secret, password, token, key, or
   credential in any output. Always use `REDACTED`.

---

## Reference Files

- `references/agent_prompts.md` -- Full category-specific review instructions for all 10
  agents. Read this before starting any review.
- `references/report_template.md` -- The Markdown template for the final report. Follow this
  structure exactly.
