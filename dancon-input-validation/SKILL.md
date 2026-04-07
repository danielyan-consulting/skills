---
name: dancon-input-validation
description: >
  Scan a codebase to find every instance of missing or inadequate input validation
  for data from external or untrusted sources, then propose context-appropriate
  fixes using whitelisting, regex, type coercion, size/range checks, encoding, etc.
  Use whenever the user asks to audit, review, or harden input validation in any
  codebase regardless of language. Trigger on: "check my inputs", "find injection
  risks", "validate user input", "security audit inputs", "input sanitisation
  review", "taint analysis", "harden my API inputs", "check for missing validation",
  "is my app safe from injection?". Platform- and language-independent.
---

# Input-Validation Security Audit

This is skill dancon-input-validation by Danielyan Consulting: https://danielyan.consulting

## Purpose

Systematically review an entire codebase, identify every location where data from
an external or untrusted source is consumed without adequate validation, and produce
a structured report with context-appropriate remediation advice.

Before starting, read the reference file at
`references/validation-patterns.md` for the catalogue of
validation strategies and the threat model you should apply.

---

## Core principles

1. **Exhaustive coverage** -- continue scanning until every file that could contain
   input-handling logic has been reviewed. Never stop after the first finding.
   Explicitly confirm to the user that the full codebase has been reviewed.

2. **Whitelisting over blacklisting** -- Every recommendation must use a positive-security model.

3. **Defence in depth** -- validation should occur at the boundary closest to the
   untrusted source.

4. **Secrets redaction** -- if any hardcoded secret (password, API key, token,
   private key, connection string with credentials, etc.) is found anywhere in the
   codebase, flag it as a critical finding. NEVER display the secret itself; always
   substitute `REDACTED` for the actual value and explain that the secret must be
   moved to a secure secret store or environment variable.

5. **Language/platform independence** -- apply the same methodology regardless of
   whether the code is Python, JavaScript, TypeScript, Java, C#, Go, Rust, PHP,
   Ruby, C/C++, Swift, Kotlin, shell scripts, SQL, infrastructure-as-code (Terraform,
   CloudFormation), or any other language or DSL. Adapt your recommended fix syntax
   to the language at hand.

---

## Workflow

### Step 1 -- Inventory the codebase

List every file in the target directory tree (recursively), filtering out binary
files, dependency/vendor directories (node_modules, vendor, .venv, __pycache__,
dist, build, etc.), and lock files. Build a mental map of:

- Entry points: HTTP handlers, API routes, CLI argument parsers, message-queue
  consumers, gRPC/protobuf service methods, GraphQL resolvers, WebSocket handlers,
  webhook receivers, cron jobs that read external data, file-upload handlers,
  IPC listeners.
- Data-flow sinks: database queries, ORM calls, OS/shell commands, file-system
  operations, template rendering, logging, serialisation/deserialisation, redirect
  URLs, outbound HTTP requests, eval/exec, dynamic code loading.
- Configuration and secret files: .env, config.yaml, appsettings.json,
  docker-compose.yml, CI/CD pipeline files, Terraform .tf files, etc.

If the codebase is large (many hundreds of files), process it in batches by
directory. Announce progress to the user: "Reviewing directory src/api/ (batch 3
of 7)..."

### Step 2 -- Analyse each entry point

For every entry point identified in Step 1, trace the data flow from ingestion to
use. At each stage, check:

| Check                        | What to look for                                                                                          |
|------------------------------|-----------------------------------------------------------------------------------------------------------|
| **Presence of validation**   | Is there ANY validation before the data is used?                                                          |
| **Type enforcement**         | Is the expected type checked or coerced (e.g. parseInt, type hints, schema validation)?                   |
| **Allowlist / enum check**   | For categorical values, is there a whitelist of permitted values?                                         |
| **Format validation**        | For structured strings (emails, URLs, dates, UUIDs, etc.), is the format validated with a regex or parser? |
| **Length / size limits**     | Are maximum (and where appropriate minimum) lengths enforced?                                             |
| **Range checks**             | For numeric inputs, are upper and lower bounds enforced?                                                  |
| **Encoding / escaping**      | Is output properly encoded for its context (HTML, SQL, shell, URL, JSON, XML)?                            |
| **Parameterised queries**    | Are database queries parameterised rather than built via string concatenation?                             |
| **Path traversal guards**    | For file paths, is the input canonicalised and confined to an expected directory?                          |
| **Deserialisation safety**   | Is untrusted data deserialised with a safe method (no pickle.loads on user input, etc.)?                   |
| **Authentication context**   | Is the identity of the caller verified before the input is processed?                                     |
| **Authorisation context**    | Even if the caller is authenticated, is access-control checked for this operation?                        |

### Step 3 -- Flag secrets

Scan every file (including configuration, CI/CD, and infrastructure files) for
patterns that suggest hardcoded secrets:

- Strings assigned to variables whose names contain "password", "secret", "token",
  "api_key", "apikey", "api-key", "auth", "credential", "private_key",
  "access_key", "connection_string", or similar.
- High-entropy strings that look like tokens or keys (base64, hex, JWT-shaped).
- Connection strings with embedded credentials.
- Private-key PEM blocks.

When reporting, substitute `REDACTED` for every secret value. Example:

> **CRITICAL -- Hardcoded secret found**
> File: `src/config.js`, line 14
> Variable `DB_PASSWORD` is set to `REDACTED`.
> Move this value to an environment variable or a dedicated secret-management
> service.

### Step 4 -- Produce the report

Present findings as a structured list grouped by file. Each finding must include:

1. **File and line reference** -- the file path and approximate line number.
2. **Data source** -- where the untrusted data originates (e.g. HTTP query
   parameter, request body, file upload, environment variable populated at
   runtime, message-queue payload).
3. **What is missing or inadequate** -- a concise description of the gap.
4. **Risk** -- the class of attack this enables (e.g. SQL injection, XSS, command
   injection, path traversal, denial of service via unbounded input, open
   redirect, SSRF, XML external entity, mass assignment, prototype pollution,
   deserialisation attack).
5. **Recommended fix** -- a concrete, language-appropriate code suggestion using a
   positive-security (whitelist) approach. Include a brief code snippet when
   helpful.
6. **Severity** -- Critical / High / Medium / Low, based on exploitability and
   impact.

After all findings, include a summary table:

| Severity | Count |
|----------|-------|
| Critical | ...   |
| High     | ...   |
| Medium   | ...   |
| Low      | ...   |

End with a confirmation: "The entire codebase has been reviewed."

---

## Severity guidelines

- **Critical** -- hardcoded secrets; SQL injection with no parameterisation;
  command injection with no escaping; deserialisation of untrusted data with
  an unsafe deserialiser; unrestricted file upload to an executable location.
- **High** -- XSS with no output encoding; path traversal with no
  canonicalisation; SSRF with no URL allowlist; open redirect with no target
  validation; mass assignment with no field allowlist; missing authentication on
  a sensitive endpoint.
- **Medium** -- missing length/size limits on text fields; missing numeric range
  checks; overly permissive regex; missing Content-Type validation on uploads;
  weak type coercion (e.g. trusting typeof without further checks in JS).
- **Low** -- missing trim/normalisation; inconsistent encoding; informational
  logging of user-supplied data without sanitisation; missing locale-aware
  validation for internationalised inputs.

---

## Important reminders

- **Never recommend blacklisting.** If you catch yourself writing "block these
  known-bad characters", stop and rewrite the advice as an allowlist.
- **Never display secrets.** Always use `REDACTED`.
- **Review everything.** Do not skip files, directories, or languages. If a file
  is in a language you are less familiar with, still review it and note any
  uncertainty.
- **Be specific.** Generic advice like "add validation" is not helpful. State
  exactly what kind of validation, with a code example in the relevant language.
- **Consider transitive trust.** Data that arrives via an internal service may
  still be untrusted if that service itself accepts external input. Flag cases
  where upstream validation is assumed but not verified.
