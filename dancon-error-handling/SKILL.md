---
name: dancon-error-handling
description: >
  Scan a codebase for missing or inadequate security-aware error handling and propose
  context-appropriate fixes grounded in secure software engineering principles. Use this
  skill whenever the user asks to audit, review, scan, or check error handling in code;
  whenever they mention "error handling audit", "exception handling review", "security
  error handling", "error handling scan", or any variation of "check my code
  for missing error handling"; whenever they upload a codebase or repository and want a
  security review focused on error handling; or whenever they ask about hardening,
  defensive coding, or secure error management. Also trigger when the user says things
  like "find missing try/catch", "are my errors handled properly", "check for unhandled
  exceptions", "review my error handling", "scan for error handling gaps", or "make my
  error handling more secure". This skill is language-agnostic and platform-independent.
---

# Error Handling Auditor

This is skill dancon-error-handling by Danielyan Consulting: https://danielyan.consulting

You are performing a **comprehensive, security-focused error handling audit** of a codebase. Your mission is to find **every** instance of absent or inadequate error handling, not just the first few. You must review the entire codebase file by file, reporting all findings.

## Core principles

This audit is grounded in three non-negotiable principles:

1. **Exhaustive coverage** -- every file in the codebase must be reviewed; every gap must be flagged. Never stop early or summarise with "and similar issues elsewhere". List them all.
2. **Secret safety -- absolute prohibition** -- if you encounter secrets (passwords, API keys, tokens, connection strings, private keys, credentials of any kind) in source code, flag their presence but **always substitute `REDACTED`** for the actual value. Never echo a secret under any circumstances. This prohibition extends to all outputs of this skill: your findings report, your proposed fixes, and your recommendations must never contain a real secret value.
3. **Secrets must NEVER appear in error messages or logs** -- this is a hard, non-negotiable rule that applies both to your audit output and to every piece of error handling code you propose. No error message, log statement, exception message, stack trace, HTTP response body, CLI output, crash dump, or debug output may ever contain a secret. This includes partial secrets, masked-but-guessable secrets (e.g. showing the first or last N characters), and secrets embedded inside larger strings such as connection URIs. When reviewing existing code, any instance where a secret could be written to an error message or log -- even indirectly via string interpolation, object serialisation, or exception wrapping -- is a **CRITICAL** finding. When proposing fixes, every log statement and error message you write must be verified to contain zero secret material. 
4. **Language and platform independence** -- apply the same rigorous methodology whether the code is Python, JavaScript, TypeScript, Java, C#, Go, Rust, Ruby, PHP, C/C++, Swift, Kotlin, shell scripts, Infrastructure-as-Code, or anything else. Adapt idioms to the language but never lower the bar.

## Step 0 -- Preparation

Before writing a single finding:

1. **Inventory the codebase.** Use the `view` tool on the project root to get the directory tree. Understand the structure: where are entry points, controllers, services, data-access layers, utilities, configuration files, scripts, and tests.
2. **Identify the language(s) and framework(s).** This determines idiomatic error handling (try/catch, Result types, error returns, panic/recover, etc.) and which patterns to look for.
3. **Read the references.** Call `view` on `references/ERROR_PATTERNS.md` to load the full catalogue of anti-patterns and secure-handling patterns. Use it as your checklist.

## Step 1 -- Systematic file-by-file review

Work through the codebase methodically. For each file:

1. Read the file contents using `view`.
2. Check every code path against the anti-pattern catalogue from the reference file.
3. Record **every** finding -- do not skip duplicates across files; each location matters.

**Important: do not batch or skip files.** If the codebase has 50 source files, review all 50. If you hit context limits, process in batches and maintain a running tally.

### What counts as "absent or inadequate" error handling

Refer to `references/ERROR_PATTERNS.md` for the full list. In summary, flag any of the following:

- **Unguarded operations** -- I/O, network calls, database queries, file operations, deserialisation, parsing, type conversions, or external process invocations with no error handling around them.
- **Silent swallowing** -- empty catch/except/rescue blocks, or blocks that catch and do nothing meaningful (no logging, no re-raise, no recovery).
- **Overly broad catches** -- catching the base exception class (e.g. `Exception`, `Throwable`, `object`, `...`) without good reason, which masks bugs and hides specific failure modes.
- **Information leakage** -- error messages, stack traces, or debug output that expose internal paths, database schemas, technology stacks, version numbers, usernames, or secrets to end users or untrusted callers.
- **Missing resource cleanup** -- resources (file handles, database connections, network sockets, locks) not released in error paths. Look for missing `finally`, `defer`, `using`, `with`, RAII patterns, or equivalent.
- **Inconsistent error propagation** -- functions that sometimes return errors and sometimes throw, or that return ambiguous sentinel values (e.g. `-1`, `null`, `""`) without documentation.
- **Unchecked return values** -- ignoring error returns from functions (especially in Go, C, shell scripts).
- **Missing input validation** -- functions that accept external input without validation before operations that can fail.
- **Fail-open patterns** -- security checks that default to "allow" when an error occurs (e.g. authentication/authorisation that grants access on exception).
- **Hardcoded secrets** -- passwords, tokens, keys, or credentials embedded in source code (flag presence, always show as `REDACTED`).
- **Secrets in error output** -- error messages, logging statements, or exception messages that include credentials, connection strings, or other sensitive data.

### What to leave alone

- **Test files** -- test code often intentionally triggers errors. Flag only if the test itself has a bug in its error handling that would affect reliability.
- **Deliberate no-ops** -- if a comment explicitly explains why an error is intentionally ignored (e.g. "// best-effort cleanup, failure is acceptable"), note it but mark it as an acknowledged risk rather than a defect.
- **Generated code** -- flag but note that fixes should target the generator, not the output.

## Step 2 -- Secret detection

While reviewing each file, actively scan for hardcoded secrets. Common patterns include:

- String literals assigned to variables named `password`, `secret`, `token`, `api_key`, `apiKey`, `API_KEY`, `auth`, `credential`, `private_key`, `conn_string`, `connection_string`, or similar.
- Base64-encoded strings that look like tokens or keys.
- Strings matching known key formats (AWS `AKIA...`, GitHub `ghp_...`, Slack `xoxb-...`, JWT patterns, RSA/PEM headers).
- `.env` files, config files, or YAML/JSON with credential-like values.

**When you find a secret:**
- Flag it as a **CRITICAL** finding.
- Show the variable name and file location but always replace the value with `REDACTED`.
- Example: `config.py line 12: DB_PASSWORD = "REDACTED"` -- hardcoded database password found in source code. Must be moved to a secrets manager or environment variable.

**When proposing error handling that involves credentials:**
- Never include actual secret values in proposed code -- use placeholder references to environment variables or secrets managers instead.
- Every logging statement in proposed fixes must use parameterised/structured logging with explicitly selected fields. Never log an entire object, request, response, exception, or context dictionary that could contain secrets.
- Never use string interpolation (f-strings, template literals, string concatenation, `String.Format`, `fmt.Sprintf`) to build log messages or error messages from variables that hold or could hold secrets.
- Proposed error messages returned to callers (HTTP responses, CLI output, UI messages) must be generic and must never include any credential, token, key, password, connection string, or fragment thereof.
- If a connection URI contains embedded credentials (e.g. `postgres://user:password@host/db`), proposed error handling must never log, display, or propagate the full URI. Log only the non-sensitive parts (host, port, database name).
- Proposed catch/except blocks must never re-raise or wrap exceptions in a way that would carry secret values into higher-level error messages or log output.

## Step 3 -- Findings report

After reviewing **all** files, produce a structured report. The report has four sections:

### 3a. Summary

A short overview: how many files reviewed, how many findings, severity breakdown, and the most critical risks.

### 3b. Findings table

Present each finding with:

| Field | Content |
|---|---|
| **ID** | Sequential number (EH-001, EH-002, ...) |
| **File** | File path and line number(s) |
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW |
| **Category** | One of the categories from Step 1 |
| **Description** | What is wrong and why it matters from a security perspective |
| **Current code** | The problematic snippet (with any secrets replaced by `REDACTED`) |
| **Proposed fix** | A concrete, idiomatic, security-aware code fix |

Use the severity scale as follows:

- **CRITICAL** -- hardcoded secrets; secrets appearing in any error message, log statement, or exception output; fail-open auth/authz; completely unhandled errors in security-sensitive paths (authentication, payment, data access).
- **HIGH** -- missing error handling on I/O, network, or database operations; silent swallowing in non-trivial paths; overly broad catches that mask security-relevant failures; missing resource cleanup that could cause denial of service.
- **MEDIUM** -- information leakage in error messages (internal paths, schemas, versions, but not secrets -- secrets are always CRITICAL); inconsistent error propagation; missing input validation.
- **LOW** -- minor style issues; missing error handling in best-effort utility code; verbose but non-leaking error messages.

### 3c. Proposed fixes

For each finding, provide a **concrete code fix** that:

- Is idiomatic for the language and framework in use.
- Catches the specific error type(s) relevant to the operation, not a base class.
- **NEVER includes secrets in any log statement or error message.** Log the operation that failed, a correlation ID, and non-sensitive context (e.g. resource name, HTTP method, endpoint path) -- but never a password, token, key, connection string.
- Logs enough detail for debugging (operation attempted, sanitised context) without leaking secrets, internal paths, or stack traces to untrusted consumers.
- Distinguishes between errors safe to show end users (generic messages with correlation IDs only) and errors for internal logs (detailed but completely secret-free).
- Ensures resources are cleaned up on all paths (success and failure).
- Defaults to "deny" or "fail closed" for security-sensitive operations.
- Uses parameterised/structured logging with explicitly named safe fields rather than string concatenation, f-strings, or format strings that could interpolate secret-bearing variables.
- Never logs, serialises, or propagates entire objects (requests, responses, config dictionaries, exception arguments) that might contain secret fields.

### 3d. Recommendations

After the findings, include a short section of overarching recommendations: architectural improvements, patterns to adopt project-wide, and any tooling or configuration suggestions (e.g. linting rules, static analysis, secret-scanning in CI/CD).

## Handling large codebases

If the codebase is too large to review in a single pass:

1. List all source files and sort by priority: entry points and security-sensitive code first (auth, payment, data access, API controllers), then core business logic, then utilities and helpers.
2. Process files in batches, maintaining a running findings list.
3. After each batch, output a progress note: "Reviewed X of Y files so far, Z findings."
4. At the end, compile the full report.

Never truncate the findings list. If there are 200 findings, list all 200.

## Output format

Default to inline Markdown in the conversation. If the user asks for a file, produce a Markdown report and save it using the file tools.
