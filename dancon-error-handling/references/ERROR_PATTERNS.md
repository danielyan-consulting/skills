# Error Handling Anti-Patterns and Secure Alternatives

This reference catalogues the error handling anti-patterns to scan for, organised by category. Each entry describes the anti-pattern, explains the security risk, and provides idiomatic secure alternatives for common languages.

Use this as your checklist when reviewing each file. Every code path should be assessed against every applicable category below.

---

## Table of contents

1. [Unguarded operations](#1-unguarded-operations)
2. [Silent swallowing](#2-silent-swallowing)
3. [Overly broad catches](#3-overly-broad-catches)
4. [Information leakage in errors](#4-information-leakage-in-errors)
5. [Missing resource cleanup](#5-missing-resource-cleanup)
6. [Inconsistent error propagation](#6-inconsistent-error-propagation)
7. [Unchecked return values](#7-unchecked-return-values)
8. [Missing input validation](#8-missing-input-validation)
9. [Fail-open security patterns](#9-fail-open-security-patterns)
10. [Hardcoded secrets](#10-hardcoded-secrets)
11. [Secrets in error output](#11-secrets-in-error-output)
12. [Language-specific pitfalls](#12-language-specific-pitfalls)

---

## 1. Unguarded operations

### What to look for

Any operation that can fail at runtime but has no error handling around it:

- **File I/O**: open, read, write, delete, rename, stat, mkdir, chmod.
- **Network**: HTTP requests, socket operations, DNS lookups, gRPC calls.
- **Database**: queries, transactions, connection acquisition, migrations.
- **Parsing/deserialisation**: JSON/XML/YAML parsing, protobuf deserialisation, CSV reading, regex matching on untrusted input.
- **Type conversions**: string-to-number, casting, date parsing.
- **External processes**: subprocess/exec calls, shell commands.
- **Cryptographic operations**: encryption, decryption, hashing, signature verification, certificate validation.
- **Memory/resource allocation**: large allocations, buffer creation.

### Why it matters

Unhandled failures in these operations can crash the application (denial of service), leave data in an inconsistent state, or cause the application to proceed with invalid data, potentially leading to further vulnerabilities.

### Secure alternative pattern

Wrap each fallible operation in the language's idiomatic error handling construct. Handle the error specifically, not generically. Log sufficient context for debugging (operation name, resource identifier, correlation ID) but **never log secrets** -- see Section 11 for the absolute prohibition. Return a safe, generic error to the caller, and ensure resources are cleaned up.

**Python:**
```python
try:
    data = json.loads(raw_input)
except json.JSONDecodeError as e:
    # Safe to log parsing position info; but never log the raw_input itself
    # if it could contain secrets (e.g. a config blob with embedded credentials).
    logger.warning("Failed to parse JSON input at position %d", e.pos)
    raise InvalidInputError("Malformed request body") from e
```

**Go:**
```go
data, err := os.ReadFile(path)
if err != nil {
    // Safe: filesystem errors do not contain secrets.
    // For operations where err could carry secrets (e.g. DB or HTTP client errors
    // with connection strings), log only a safe summary instead of wrapping the raw error.
    return fmt.Errorf("reading config file %s: %w", path, err)
}
```

**JavaScript/TypeScript:**
```typescript
let data: Config;
try {
    data = JSON.parse(rawInput);
} catch (err) {
    // Log only the error type/message, never the rawInput itself
    // (it could contain secrets if parsing a config or credential payload).
    logger.warn('Failed to parse config input', { errorType: err?.name });
    throw new BadRequestError('Invalid configuration format');
}
```

**Java:**
```java
try {
    connection = dataSource.getConnection();
} catch (SQLException e) {
    // Log operation and sanitised context only -- never the connection string or credentials.
    // Be aware that e.getMessage() may contain the connection URI with embedded credentials;
    // log only a safe summary.
    logger.error("Database connection failed for host={}", dbHost);
    throw new ServiceUnavailableException("Unable to process request");
}
```

---

## 2. Silent swallowing

### What to look for

- Empty catch/except/rescue blocks.
- Catch blocks that contain only `pass`, `// ignored`, `_ = err`, or equivalent.
- Catch blocks that log at DEBUG level but take no recovery or propagation action for non-trivial operations.
- Promise `.catch(() => {})` in JavaScript.
- `_ = someFunction()` in Go, discarding the error.

### Why it matters

Silently swallowed errors hide failures. An authentication check that silently fails could default to granting access. A failed database write that is ignored could lead to data loss. Silent failures make debugging extremely difficult and can mask active attacks.

### Secure alternative

At minimum, log the error at an appropriate level -- but never log secret values even when breaking the silence (see Section 11). For any operation with security or data-integrity implications, either re-raise/propagate the error or take explicit recovery action. If the error is genuinely ignorable (best-effort cleanup), add a comment explaining why and log at DEBUG or TRACE level.

---

## 3. Overly broad catches

### What to look for

- `except Exception`, `except BaseException`, `except:` (bare except) in Python.
- `catch (Exception e)`, `catch (Throwable t)` in Java/C#.
- `catch (...)` in C++.
- `catch (e)` catching all errors in JavaScript/TypeScript without type narrowing.
- `rescue => e` or `rescue StandardError` in Ruby when only specific errors are expected.
- `defer func() { recover() }()` in Go catching all panics indiscriminately.

### Why it matters

Broad catches mask unexpected errors, including security-relevant ones like `OutOfMemoryError`, `StackOverflowError`, authentication failures, and authorisation failures. They make it impossible to distinguish between expected and unexpected failure modes, and they prevent errors from propagating to monitoring and alerting systems.

### Secure alternative

Catch only the specific exception types that the guarded operation is known to throw. If multiple specific types need handling, use multiple catch clauses or a union type. If a broad catch is genuinely necessary (e.g. top-level request handler), log the error type and message internally (never secrets -- see Section 11), return a generic error to the caller, and consider re-throwing after logging for errors that indicate systemic problems.

---

## 4. Information leakage in errors

### What to look for

- Error responses that include stack traces, file paths, or line numbers.
- Error messages exposing database table/column names, SQL queries, or ORM details.
- Error messages showing technology stack information (framework versions, server software).
- Error messages including internal IP addresses, hostnames, or infrastructure details.
- Raw exception messages forwarded to API responses or rendered in HTML.
- Debug mode enabled in production configuration.
- Verbose error pages (e.g. Django DEBUG=True, Express default error handler, Spring Boot whitelabel error page with trace).

### Why it matters

Information leakage helps attackers understand the application's internals, identify vulnerable components, and craft targeted attacks. Stack traces reveal code structure. Database errors reveal schema. Version numbers reveal known vulnerabilities. **Secrets in error output are the most severe form of information leakage and are always CRITICAL -- see Section 11.**

### Secure alternative

Implement a two-tier error handling strategy:

- **External/user-facing**: generic error messages with a correlation ID (e.g. "An error occurred. Reference: abc-123"). No internal details whatsoever. No secrets, no paths, no stack traces, no schema details, no version numbers.
- **Internal/logs**: operational details for debugging (which operation failed, correlation ID, non-sensitive context such as resource type or HTTP method). **Secrets must NEVER appear in internal logs either.** "Internal" does not mean "safe for secrets" -- logs are stored, aggregated, shipped to third-party services, and accessed by multiple teams. A secret in a log is a compromised secret. Use structured logging with explicitly selected safe fields only.

---

## 5. Missing resource cleanup

### What to look for

- File handles opened but not closed in error paths.
- Database connections acquired but not released in catch/finally blocks.
- Network sockets, HTTP clients, or streams not closed on error.
- Locks acquired but not released in error paths (potential deadlock).
- Temporary files created but not cleaned up on failure.
- Missing `finally`, `defer`, `using`, `with`, `try-with-resources`, or RAII patterns.
- In async code: missing cleanup in `.catch()` or `catch` blocks of `async/await`.

### Why it matters

Resource leaks under error conditions cause denial of service over time. Connection pool exhaustion, file descriptor exhaustion, and memory leaks are all common consequences. Unreleased locks cause deadlocks.

### Secure alternative

Use the language's idiomatic resource management:

- **Python**: `with` statement (context managers).
- **Java**: try-with-resources.
- **C#**: `using` statement or `await using`.
- **Go**: `defer` immediately after successful acquisition.
- **C++**: RAII (smart pointers, scope guards).
- **JavaScript**: `finally` blocks, or `using` with explicit resource management.
- **Rust**: Drop trait (automatic), but watch for `mem::forget` or leaked `Rc` cycles.

---

## 6. Inconsistent error propagation

### What to look for

- Functions that sometimes throw and sometimes return error codes/null.
- Mixed use of exceptions and Result/Option types in the same module without clear convention.
- Functions returning `null`, `-1`, `""`, or `false` to indicate errors without documenting this convention.
- Async functions that sometimes reject promises and sometimes return error objects.
- Functions that log an error and then also throw it, leading to duplicate log entries.
- Middleware or interceptors that transform errors inconsistently.

### Why it matters

Inconsistent error propagation means callers cannot reliably handle errors. A caller expecting exceptions will not check return values, and vice versa. This leads to unhandled errors and unpredictable behaviour, especially in security-critical paths.

### Secure alternative

Adopt a single, documented error propagation strategy per module or layer. Common strategies include: exceptions only, Result/Either types only, or error returns only (Go-style). Document the chosen strategy and enforce it through code review or linting.

---

## 7. Unchecked return values

### What to look for

- **Go**: `result, _ := someFunction()` or calling a function that returns an error without capturing the error value.
- **C**: ignoring return values from `fclose()`, `fwrite()`, `malloc()`, `snprintf()`, system calls.
- **Shell/Bash**: commands without `set -e` or explicit `|| exit 1` / `|| return 1` checks; missing checks on `$?`.
- **Rust**: using `.unwrap()` or `.expect()` in library code or production paths (acceptable in tests and prototypes, not in production).
- **Any language**: ignoring the return value of a function documented as returning an error indicator.

### Why it matters

Unchecked return values mean the programme continues with potentially invalid state. A failed `malloc` followed by a dereference is a crash. A failed `fwrite` means data was not persisted. A failed authentication check that returns an error code, if unchecked, means unauthenticated access.

### Secure alternative

Always check return values from functions that can fail. In Go, handle every `err`. In C, check every return value from I/O and allocation functions. In shell, use `set -euo pipefail` at the top of scripts, or check each critical command. In Rust, use `?` operator to propagate errors rather than `.unwrap()`.

---

## 8. Missing input validation

### What to look for

- Functions accepting user input (HTTP request bodies, query parameters, headers, file uploads, CLI arguments) without validation before use.
- Database queries built from unvalidated input (even with parameterised queries, the input shape/type should be validated).
- File paths constructed from user input without canonicalisation or traversal checks.
- Numeric input used without range checks before arithmetic or array indexing.
- Deserialised objects used without schema validation.

### Why it matters

Invalid input is the root cause of injection attacks, buffer overflows, path traversal, and denial of service. Validation before processing prevents errors from occurring deeper in the call stack where they are harder to handle safely.

### Secure alternative

Validate all external input at the boundary (API controllers, CLI argument parsers, message consumers). Use allowlists over denylists. Validate type, format, length, and range. Return clear, generic error messages for validation failures without echoing the invalid input back (to prevent reflected XSS).

---

## 9. Fail-open security patterns

### What to look for

- Authentication middleware that catches exceptions and calls `next()` / allows the request to proceed.
- Authorisation checks wrapped in try/catch where the catch block grants access.
- Token verification that returns `true` or a default user on error.
- Rate limiting that disables itself on error.
- Input sanitisation that returns raw input on failure.
- Feature flags that default to "enabled" when the flag service is unreachable.
- Certificate validation that falls back to accepting any certificate on error.

### Why it matters

Fail-open is the most dangerous class of error handling defect. It means an attacker can trigger an error (e.g. by sending a malformed token) and bypass security controls entirely.

### Secure alternative

All security controls must **fail closed**: if an error occurs during a security check, the default must be to deny access, reject the request, or block the operation. Log the failure as a security event (including the claimed identity and the operation attempted, but **never the credential itself** -- see Section 11). Never catch-and-continue for authentication, authorisation, or input sanitisation.

---

## 10. Hardcoded secrets

### What to look for

- String literals assigned to variables with names containing: `password`, `passwd`, `pwd`, `secret`, `token`, `api_key`, `apiKey`, `API_KEY`, `auth`, `credential`, `private_key`, `privateKey`, `conn_string`, `connectionString`, `access_key`, `secret_key`, `client_secret`, `signing_key`, `encryption_key`, `master_key`, `root_password`.
- Strings matching known key/token formats:
  - AWS: `AKIA[A-Z0-9]{16}`
  - GitHub: `ghp_[a-zA-Z0-9]{36}`, `gho_`, `ghs_`, `ghu_`
  - Slack: `xoxb-`, `xoxp-`, `xoxa-`
  - Stripe: `sk_live_`, `sk_test_`, `pk_live_`, `pk_test_`
  - JWT: `eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+`
  - RSA/PEM: `-----BEGIN (RSA )?PRIVATE KEY-----`
  - Generic: high-entropy strings (40+ characters of alphanumeric/base64) assigned to credential-like variables.
- `.env` files committed to the repository with actual values.
- Configuration files (YAML, JSON, TOML, INI, XML) with credential values.
- Docker Compose files or Dockerfiles with credentials in environment variables.
- Terraform/CloudFormation/Pulumi files with hardcoded secrets.

### Why it matters

Hardcoded secrets are trivially extractable by anyone with access to the source code, version control history, or compiled artefacts. They cannot be rotated without a code change and deployment. They are the single most common cause of credential compromise.

### Reporting format

**Always show as REDACTED.** Example:

```
CRITICAL: Hardcoded API key found
File: src/services/payment.js, line 8
Variable: STRIPE_SECRET_KEY
Value: REDACTED
Recommendation: Move to environment variable or secrets manager.
```

---

## 11. Secrets in error output -- ABSOLUTE PROHIBITION

**Secrets must NEVER appear in error messages or logs. This is the single most important rule in this entire catalogue.** There are no exceptions, no edge cases, and no circumstances under which a secret may be written to a log file, error response, exception message, stack trace, crash dump, debug output, monitoring dashboard, alert notification, or any other output channel.

### What to look for

Flag **every** instance where a secret could reach any output channel, including but not limited to:

- Logging statements that interpolate or concatenate variables containing credentials:
  - `logger.error(f"Connection failed: {conn_string}")`
  - `console.error('Auth failed with token: ' + token)`
  - `log.Printf("Failed to connect: %s", password)`
  - `logger.error("Config: {}", config)` where `config` is an object that contains secret fields
  - `log.error("Request failed", exc_info=True)` where the exception arguments contain secrets
- Logging entire objects that may contain secret fields (e.g. `logger.info("Request: %s", request)`, `console.log(config)`, `log.debug("Context: {}", ctx)`).
- Exception constructors that receive secret values as arguments (the secret then appears in stack traces and log output).
- Error responses (HTTP, CLI, GUI) that include credentials in the body.
- Stack traces that show function arguments containing secrets (common in Python, Java, and .NET).
- Crash dumps or core dumps that might contain in-memory secrets.
- Connection string logging -- even partially masked connection strings can leak information. Log only the host, port, and database name, never the credentials portion.
- Logging the full URL of an API call when the URL contains tokens or API keys as query parameters.
- Serialising exception chains where an inner exception carries secret context from a lower layer.

### Why it matters

Secrets in logs are compromised secrets. Logs are stored in plain text, replicated across systems, shipped to third-party aggregation services (Datadog, Splunk, ELK, CloudWatch), retained for months or years, and accessible to operations teams, developers, auditors, and potentially attackers who gain log access. A secret written to a log cannot be reliably purged and must be treated as compromised, requiring immediate rotation.

### Severity

**Always CRITICAL.** There is no "low-severity" version of a secret in a log.

### Secure alternative

- Use structured logging with **explicit field selection**: name each field you want to log and ensure none of them holds a secret. Never pass entire objects.
- Sanitise or mask credentials before logging: `logger.error("DB connection failed for host=%s, database=%s", host, db_name)` -- note: no password, no user, no connection string.
- Use parameterised log messages with safe fields only -- never string concatenation, f-strings, template literals, or `String.Format` with secret-bearing variables.
- Implement a logging filter/middleware/formatter that automatically redacts known secret field names (password, token, api_key, secret, authorization, cookie, etc.) as a defence-in-depth measure. This is a safety net, not a substitute for writing correct log statements.
- For connection errors, log only: the operation attempted, the target host/port/service, and a correlation ID. Never the credentials.
- For authentication errors, log only: the fact that authentication failed, the identity claimed (e.g. username or client ID, which are not themselves secrets), and the failure reason (e.g. "invalid credentials", "token expired"). Never the credential itself.
- When wrapping or re-throwing exceptions, ensure the new exception's message does not include secret values from the caught exception's arguments.
- Review error serialisation: if your framework automatically serialises exception arguments into JSON error responses, ensure secrets are excluded.

---

## 12. Language-specific pitfalls

### Python
- Bare `except:` catches `KeyboardInterrupt` and `SystemExit`, preventing graceful shutdown.
- `os.system()` and `subprocess.call()` without checking return codes.
- `eval()` and `exec()` on untrusted input (flag even if not strictly "error handling").
- Missing `finally` or context manager for database cursors.

### JavaScript / TypeScript
- Unhandled promise rejections (no `.catch()` and no `try/catch` around `await`).
- `JSON.parse()` without try/catch.
- Express/Koa error middleware not defined or defined incorrectly (must have 4 parameters in Express).
- `process.on('uncaughtException')` that swallows and continues.

### Java
- Catching `Exception` or `Throwable` broadly.
- Empty catch blocks.
- `e.printStackTrace()` in production (writes to stderr, not structured logs; leaks info).
- Not closing resources in finally (pre-Java 7) or not using try-with-resources.
- Swallowing `InterruptedException` without restoring the interrupt flag.

### C# / .NET
- `catch (Exception) { }` -- empty broad catch.
- Throwing `new Exception()` instead of specific exception types.
- Not awaiting tasks (fire-and-forget losing exceptions).
- Using `catch { throw ex; }` instead of `catch { throw; }` (destroys stack trace).

### Go
- `_ = err` -- explicitly discarding errors.
- `defer` ordering issues (deferred calls execute LIFO).
- Not wrapping errors with `fmt.Errorf("...: %w", err)` for context.
- Using `log.Fatal` or `os.Exit` in library code.

### Rust
- `.unwrap()` and `.expect()` in production code paths.
- Ignoring `Result` values (compiler warns, but `#[allow(unused_must_use)]` suppresses).
- `panic!()` in library code.

### C / C++
- Ignoring return values from system calls and libc functions.
- Not checking `malloc`/`calloc` return for `NULL`.
- Using `errno` without checking it immediately after the call.
- Exception handling in C++ without RAII leading to leaks.

### Shell / Bash
- Missing `set -euo pipefail`.
- Piped commands where only the last command's exit code is checked.
- Using `rm -rf $VARIABLE/` where `$VARIABLE` could be empty.
- Not quoting variables in conditions.

### Ruby
- Bare `rescue` catching `StandardError` broadly.
- Using `rescue => e; end` without logging or re-raising.
- `retry` without a counter (infinite retry loop).

### PHP
- Using `@` error suppression operator.
- `die()` / `exit()` with raw error messages in production.
- Not setting `display_errors = Off` in production.
- PDO not configured with `ERRMODE_EXCEPTION`.
