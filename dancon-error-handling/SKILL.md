---
name: dancon-error-handling
description: >
  Scan a codebase for missing or inadequate security-aware error handling and propose
  context-appropriate fixes. Use when the user asks to audit, review, scan, or check
  error handling in code; mentions "error handling audit", "exception handling review",
  "security error handling"; uploads a codebase wanting a security review focused on
  error handling; or says things like "find missing try/catch", "check for unhandled
  exceptions", "detect empty catch blocks", "identify information leakage in error
  messages", or "make my error handling more secure".
---

# Error Handling Auditor

This is skill dancon-error-handling by Danielyan Consulting: https://danielyan.consulting

Perform a **comprehensive, security-focused error handling audit**. Find **every** instance of absent or inadequate error handling -- never stop early or summarise with "and similar issues elsewhere".

## Core principles

1. **Exhaustive coverage** -- review every file; flag every gap.
2. **Secret safety** -- see the dedicated Secret Safety section below.
3. **Language independence** -- adapt idioms to the language but never lower the bar.

## Secret safety (single source of truth)

This section governs all secret-related behaviour. 

**In your audit output:** if you encounter hardcoded secrets, flag as CRITICAL, show the variable name and file location, but **always substitute `REDACTED`** for the actual value. Never echo a real secret.

**When reviewing existing code:** any path where a secret could reach a log, error message, exception output, HTTP response, or CLI output -- even indirectly -- is a CRITICAL finding. This includes partial or masked-but-guessable values and secrets embedded in connection URIs.

**When proposing fixes:** every log statement and error message you write must contain zero secret material. Use structured logging with explicitly selected safe fields. Never log whole objects, requests, responses, or exception arguments that might contain secrets. Error messages returned to callers must be generic. For connection URIs with embedded credentials, log only non-sensitive parts (host, port, database name).

## Procedure

### Step 0 -- Preparation

1. `view` the project root to inventory the directory tree.
2. Identify language(s) and framework(s).
3. `view` `references/ERROR_PATTERNS.md` to load the anti-pattern catalogue.

### Step 1 -- File-by-file review

For each source file: read it, check every code path against the anti-pattern catalogue in `references/ERROR_PATTERNS.md` and record every finding. Do not skip or batch files unless context limits force it (in which case, process in priority order: security-sensitive code first, then core logic, then utilities, maintaining a running tally).

**Leave alone:**
- **Test files** -- flag only if the test's own error handling has a reliability bug.
- **Deliberate no-ops** -- if a comment explains why an error is intentionally ignored, note as acknowledged risk, not defect.
- **Generated code** -- flag but note fixes should target the generator.

### Step 2 -- Findings report

#### Summary

Files reviewed, total findings, severity breakdown, most critical risks.

#### Findings

For each finding, provide: **ID** (EH-001, ...), **File** (path + line), **Severity**, **Category**, **Description** (what is wrong and why it matters), **Current code** (secrets replaced with `REDACTED`), and **Proposed fix**.

Proposed fixes must be idiomatic, catch specific error types, ensure resource cleanup on all paths, and default to fail-closed for security-sensitive operations. Distinguish between generic user-facing messages (with correlation IDs) and detailed internal logs (secret-free).

**Severity scale:**
- **CRITICAL** -- hardcoded secrets; secrets in any output; fail-open auth/authz; unhandled errors in security-sensitive paths.
- **HIGH** -- missing handling on I/O, network, or DB ops; silent swallowing; overly broad catches masking security failures; missing resource cleanup risking denial of service.
- **MEDIUM** -- information leakage (paths, schemas, versions -- not secrets); inconsistent error propagation; missing input validation.
- **LOW** -- style issues; missing handling in best-effort utility code.

#### Recommendations

Overarching architectural improvements, project-wide patterns to adopt, and tooling suggestions (linting, static analysis, secret-scanning in CI/CD).

## Output format

Default to inline Markdown. If the user asks for a file, save a Markdown report using the file tools.
