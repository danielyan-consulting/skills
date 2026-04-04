---
name: dancon-secure-coder-go
description: >
  ALWAYS use this skill whenever generating, writing, reviewing, editing, or modifying Go (.go) code
  in any context. This skill ensures all generated Go code avoids the CWE Top 25 2025 weaknesses that
  apply to Go, and that every piece of Go code includes appropriate input validation, thorough error
  handling, and safe error messages that never leak passwords, tokens, API keys, or other secrets.
  The Go `unsafe` package is absolutely prohibited and must never appear in generated code.
  Trigger on ANY Go code generation -- there are no exceptions. Even trivial examples and one-off
  snippets must follow these rules. If the user asks for Go code, read this skill first.
---

# Secure Go Code Generator skill compliant with CWE Top 25 2025

This is skill dancon-secure-coder-go by Danielyan Consulting: https://danielyan.consulting

This skill is mandatory for ALL Go code generation. Read it before writing any Go code.

## Core Principles

1. **Validate all input** -- every function that accepts external data must validate it before use.
2. **Handle every error** -- never discard errors with `_`; always check and handle them.
3. **Never leak secrets in errors** -- error messages must never contain passwords, tokens, API keys, connection strings with credentials, or any secret material. Log sanitised context only.
4. **Defence in depth** -- apply multiple layers of protection; do not rely on a single check.
5. **Principle of least privilege** -- request only the permissions and access actually needed.
6. **Never use the `unsafe` package** -- the `unsafe` package is absolutely prohibited. Do not import it, do not use `unsafe.Pointer`, `unsafe.Sizeof`, `unsafe.Alignof`, `unsafe.Offsetof`, or `unsafe.Slice`. There are no exceptions. If a task appears to require `unsafe`, find a safe alternative using the standard library or a well-maintained third-party package. If no safe alternative exists, explain the limitation to the user rather than generating unsafe code.

---

## CWE Top 25 2025 -- Go Applicability Map

The following table shows each CWE, whether it applies to Go, and a brief rationale.
Detailed rules for each applicable CWE follow in the next section.

| Rank | CWE | Name | Applies to Go? | Rationale |
|------|--------|----------------------------------------------|----------------|-----------|
| 1 | CWE-79 | Cross-site Scripting (XSS) | YES | Go `html/template` and `net/http` are used for web apps |
| 2 | CWE-89 | SQL Injection | YES | Go `database/sql` is widely used |
| 3 | CWE-352 | Cross-Site Request Forgery (CSRF) | YES | Go web servers must implement CSRF protection |
| 4 | CWE-862 | Missing Authorisation | YES | Authorisation logic is application-level |
| 5 | CWE-787 | Out-of-bounds Write | NO | Go has bounds-checked slices and arrays; no raw pointer arithmetic |
| 6 | CWE-22 | Path Traversal | YES | `os.Open`, `filepath.Join` can be exploited |
| 7 | CWE-416 | Use After Free | NO | Go is garbage-collected; no manual memory management |
| 8 | CWE-125 | Out-of-bounds Read | NO | Go has bounds-checked slices and arrays |
| 9 | CWE-78 | OS Command Injection | YES | `os/exec` can be misused |
| 10 | CWE-94 | Code Injection | YES | Possible via `text/template`, plugin loading, or eval-like patterns |
| 11 | CWE-120 | Classic Buffer Overflow | NO | Go is memory-safe |
| 12 | CWE-434 | Unrestricted Upload of File with Dangerous Type | YES | Go web servers handling file uploads |
| 13 | CWE-476 | NULL Pointer Dereference | YES | Go has nil pointer panics |
| 14 | CWE-121 | Stack-based Buffer Overflow | NO | Go is memory-safe |
| 15 | CWE-502 | Deserialisation of Untrusted Data | YES | `encoding/json`, `encoding/gob`, `encoding/xml` |
| 16 | CWE-122 | Heap-based Buffer Overflow | NO | Go is memory-safe |
| 17 | CWE-863 | Incorrect Authorisation | YES | Authorisation logic is application-level |
| 18 | CWE-20 | Improper Input Validation | YES | Fundamental to all Go code |
| 19 | CWE-284 | Improper Access Control | YES | Application-level concern |
| 20 | CWE-200 | Exposure of Sensitive Information | YES | Error messages, logs, API responses |
| 21 | CWE-306 | Missing Authentication for Critical Function | YES | Application-level concern |
| 22 | CWE-918 | Server-Side Request Forgery (SSRF) | YES | Go `net/http` client calls |
| 23 | CWE-77 | Command Injection | YES | Similar to CWE-78; `os/exec` misuse |
| 24 | CWE-639 | Authorisation Bypass Through User-Controlled Key | YES | IDOR vulnerabilities in Go APIs |
| 25 | CWE-770 | Allocation of Resources Without Limits | YES | Goroutine/memory exhaustion |

**Excluded (not applicable to Go):** CWE-787, CWE-416, CWE-125, CWE-120, CWE-121, CWE-122 -- these are memory-safety issues handled by Go's runtime. Go does not have raw pointer arithmetic, manual memory management, or unchecked buffer operations.

**ABSOLUTE PROHIBITION -- `unsafe` package:** The `unsafe` package MUST NEVER be used in any generated Go code. Do not import `"unsafe"`. Do not use `unsafe.Pointer`, `unsafe.Sizeof`, `unsafe.Alignof`, `unsafe.Offsetof`, `unsafe.Slice`, or `unsafe.Add`. Do not use `reflect.SliceHeader` or `reflect.StringHeader` (which require `unsafe` to be useful). Do not use `//go:linkname` directives. Do not use `cgo` in ways that bypass Go's memory safety. If the user explicitly requests use of `unsafe`, explain that this skill prohibits it and suggest safe alternatives. This prohibition exists because `unsafe` re-introduces the entire class of memory-safety vulnerabilities (CWE-787, CWE-416, CWE-125, CWE-120, CWE-121, CWE-122) that Go otherwise prevents.

---

## Detailed Rules for Each Applicable CWE

### CWE-79: Cross-site Scripting (XSS)

**ALWAYS:**
- Use `html/template` (not `text/template`) for HTML output.
- Use the template's built-in contextual auto-escaping; do not bypass it with `template.HTML()`, `template.JS()`, or `template.CSS()` unless the data is provably safe and a comment explains why.
- Set `Content-Type` headers explicitly (e.g. `application/json` for JSON APIs).
- Set security headers: `X-Content-Type-Options: nosniff`, `Content-Security-Policy`.

**NEVER:**
- Concatenate user input into HTML strings with `fmt.Sprintf` or string concatenation.
- Use `text/template` for HTML rendering.
- Write user-controlled data directly into `http.ResponseWriter` without escaping.

```go
// GOOD
tmpl := template.Must(template.ParseFiles("page.html"))
tmpl.Execute(w, data) // auto-escaped

// BAD -- never do this
fmt.Fprintf(w, "<h1>%s</h1>", userInput)
```

### CWE-89: SQL Injection

**ALWAYS:**
- Use parameterised queries with `?` or `$N` placeholders.
- Use `db.Query(query, args...)`, `db.Exec(query, args...)`, `db.QueryRow(query, args...)`.
- Use a query builder or ORM that parameterises automatically (e.g. `sqlx`, `squirrel`, `GORM`).

**NEVER:**
- Build SQL strings with `fmt.Sprintf`, `+`, or `strings.Join` using user input.
- Use `string` interpolation for table or column names without an allowlist.

```go
// GOOD
rows, err := db.Query("SELECT name FROM users WHERE id = $1", userID)

// BAD -- never do this
rows, err := db.Query("SELECT name FROM users WHERE id = " + userID)
```

For dynamic identifiers (table names, column names), use a strict allowlist:
```go
allowedColumns := map[string]bool{"name": true, "email": true, "created_at": true}
if !allowedColumns[col] {
    return fmt.Errorf("invalid column: %q", col)
}
query := fmt.Sprintf("SELECT %s FROM users WHERE id = $1", col)
```

### CWE-352: Cross-Site Request Forgery (CSRF)

**ALWAYS:**
- Use a CSRF protection library (e.g. `gorilla/csrf`, `justinas/nosurf`) for state-changing endpoints.
- Verify `Origin` or `Referer` headers as an additional layer.
- Use `SameSite=Lax` or `SameSite=Strict` on session cookies.

**NEVER:**
- Rely solely on cookies for authentication of state-changing requests without CSRF tokens.

### CWE-862: Missing Authorisation / CWE-863: Incorrect Authorisation / CWE-284: Improper Access Control / CWE-639: Authorisation Bypass Through User-Controlled Key

**ALWAYS:**
- Check authorisation on every endpoint and every sensitive operation, not just at the router level.
- Derive the user/resource identity from the authenticated session or token -- never from user-supplied request parameters alone (prevents IDOR).
- Compare resource ownership server-side: `if resource.OwnerID != authenticatedUser.ID { return errForbidden }`.
- Use middleware for role/permission checks where appropriate.

**NEVER:**
- Trust client-supplied user IDs, role claims, or resource IDs without server-side verification.
- Assume that obscure or sequential IDs provide security (use UUIDs and still check ownership).

```go
// GOOD -- derive user from session, check ownership
func getOrder(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value(ctxUserID).(string)
    orderID := chi.URLParam(r, "orderID")

    order, err := db.GetOrder(r.Context(), orderID)
    if err != nil {
        http.Error(w, "order not found", http.StatusNotFound)
        return
    }
    if order.UserID != userID {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    // ... serve the order
}
```

### CWE-22: Path Traversal

**ALWAYS:**
- Use `filepath.Clean` and then verify the cleaned path is within the intended base directory.
- Use `filepath.Rel` or `strings.HasPrefix` on the cleaned, absolute path against the base directory.
- Reject paths containing `..` after cleaning if they escape the base.

**NEVER:**
- Pass user input directly to `os.Open`, `os.ReadFile`, `os.Create`, or `http.ServeFile`.
- Rely solely on `filepath.Join` -- it does not prevent traversal.

```go
func safePath(baseDir, userPath string) (string, error) {
    // Clean and resolve to absolute
    absBase, err := filepath.Abs(baseDir)
    if err != nil {
        return "", fmt.Errorf("resolving base directory: %w", err)
    }
    joined := filepath.Join(absBase, filepath.Clean("/"+userPath))
    absJoined, err := filepath.Abs(joined)
    if err != nil {
        return "", fmt.Errorf("resolving path: %w", err)
    }
    // Ensure it is within the base directory
    if !strings.HasPrefix(absJoined, absBase+string(filepath.Separator)) && absJoined != absBase {
        return "", fmt.Errorf("path escapes base directory")
    }
    return absJoined, nil
}
```

### CWE-78 / CWE-77: OS Command Injection / Command Injection

**ALWAYS:**
- Pass command arguments as separate elements in `exec.Command(name, args...)` -- never as a single shell string.
- Validate and sanitise all arguments against an allowlist of expected values.
- Prefer Go standard library functions over shelling out (e.g. use `os.Rename` instead of `exec.Command("mv", ...)`).

**NEVER:**
- Use `exec.Command("sh", "-c", userInput)` or `exec.Command("bash", "-c", userInput)`.
- Concatenate user input into a command string.

```go
// GOOD
cmd := exec.Command("convert", inputFile, "-resize", "200x200", outputFile)

// BAD -- never do this
cmd := exec.Command("sh", "-c", "convert "+userInput+" -resize 200x200 out.png")
```

### CWE-94: Code Injection

**ALWAYS:**
- When using `text/template`, treat template strings as code -- never allow user input to define template content.
- Avoid `plugin.Open` with user-controlled paths.
- Avoid evaluating user-supplied expressions at runtime.

**NEVER:**
- Parse user-supplied strings as Go templates.
- Dynamically load plugins from untrusted sources.

### CWE-434: Unrestricted Upload of File with Dangerous Type

**ALWAYS:**
- Validate file type by inspecting content (use `http.DetectContentType` or magic bytes), not just the file extension or `Content-Type` header.
- Enforce maximum file size with `http.MaxBytesReader`.
- Store uploaded files outside the web root with generated (non-user-controlled) filenames.
- Use an allowlist of permitted MIME types.

```go
r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10 MB limit

file, header, err := r.FormFile("upload")
if err != nil {
    http.Error(w, "upload failed", http.StatusBadRequest)
    return
}
defer file.Close()

buf := make([]byte, 512)
n, err := file.Read(buf)
if err != nil {
    http.Error(w, "unable to read file", http.StatusBadRequest)
    return
}
contentType := http.DetectContentType(buf[:n])
allowedTypes := map[string]bool{"image/png": true, "image/jpeg": true}
if !allowedTypes[contentType] {
    http.Error(w, "file type not allowed", http.StatusUnsupportedMediaType)
    return
}
```

### CWE-476: NULL Pointer Dereference (nil pointer panic)

**ALWAYS:**
- Check interface values and pointers for nil before dereferencing.
- Check error returns before using the associated value.
- Use the comma-ok idiom for type assertions: `val, ok := x.(Type)`.
- Initialise maps before use (`make(map[K]V)`).
- Initialise struct pointer fields before access.

**NEVER:**
- Assume a pointer or interface return is non-nil without checking.
- Use bare type assertions (`val := x.(Type)`) -- always use the two-value form.

```go
// GOOD
val, ok := x.(string)
if !ok {
    return fmt.Errorf("unexpected type: %T", x)
}

// BAD -- panics if x is not a string
val := x.(string)
```

### CWE-502: Deserialisation of Untrusted Data

**ALWAYS:**
- Limit the size of input before decoding: wrap readers with `io.LimitReader`.
- Decode into concrete, well-defined structs -- not into `interface{}` or `map[string]interface{}`.
- Validate all decoded fields after unmarshalling (range checks, required fields, format checks).
- Set `json.Decoder.DisallowUnknownFields()` when appropriate.
- Be especially cautious with `encoding/gob` -- it can instantiate arbitrary types.

**NEVER:**
- Decode `encoding/gob` from untrusted sources.
- Decode unlimited input without size constraints.
- Trust decoded data without post-decode validation.

```go
decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20)) // 1 MB limit
decoder.DisallowUnknownFields()
var req CreateUserRequest
if err := decoder.Decode(&req); err != nil {
    http.Error(w, "invalid request body", http.StatusBadRequest)
    return
}
if err := req.Validate(); err != nil {
    // Log the detail server-side; return a generic message to the client
    slog.Warn("request validation failed", "error", err)
    http.Error(w, "invalid request data", http.StatusUnprocessableEntity)
    return
}
```

### CWE-20: Improper Input Validation

**ALWAYS:**
- Validate type, length, range, and format of all external inputs.
- Use allowlists over denylists wherever possible.
- Validate as early as possible in the call chain.
- For string inputs: check length limits, character sets, and format (regexp if needed).
- For numeric inputs: check min/max bounds.
- For enum-like inputs: check against a known set of valid values.

```go
func validateUsername(s string) error {
    if len(s) < 3 || len(s) > 32 {
        return errors.New("username must be between 3 and 32 characters")
    }
    if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(s) {
        return errors.New("username contains invalid characters")
    }
    return nil
}
```

### CWE-200: Exposure of Sensitive Information to an Unauthorised Actor

**ALWAYS:**
- Return generic error messages to clients (e.g. "authentication failed", "internal server error").
- Log detailed errors server-side with structured logging, but NEVER log passwords, tokens, API keys, bearer tokens, session IDs, or connection strings containing credentials.
- Sanitise error messages before returning them in HTTP responses.
- Strip stack traces from production error responses.
- Use different error detail levels for development vs. production.

**NEVER include any of these in error messages, logs, or API responses:**
- Passwords or password hashes
- API keys, tokens, bearer tokens, JWTs (except for identifying prefixes if needed for debugging, e.g. "token starting with 'eyJ...'")
- Database connection strings containing credentials
- Private keys, certificates, or secret material
- Session identifiers in client-facing errors
- Full stack traces in production responses
- Internal file paths that reveal system architecture

**NEVER pass `err.Error()` directly into HTTP responses.** The `err.Error()` string may contain internal details such as file paths, database error text, driver messages, stack frames, or wrapped context from deeper in the call chain -- none of which should be exposed to clients. Instead, return a fixed, generic message and log the real error server-side.

```go
// GOOD -- generic message to client, detail logged server-side
if err := doSomething(); err != nil {
    slog.Error("operation failed", "error", err)
    http.Error(w, "internal server error", http.StatusInternalServerError)
    return
}

// GOOD -- for validation errors, return a generic category, not the raw error
if err := req.Validate(); err != nil {
    slog.Warn("validation failed", "error", err)
    http.Error(w, "invalid request data", http.StatusBadRequest)
    return
}

// BAD -- err.Error() can leak internal details to the client
http.Error(w, err.Error(), http.StatusInternalServerError)

// BAD -- concatenating err.Error() is equally dangerous
http.Error(w, "failed: "+err.Error(), http.StatusBadRequest)

// BAD -- fmt.Sprintf with %v or %s on err exposes the same details
http.Error(w, fmt.Sprintf("error: %v", err), http.StatusInternalServerError)
```

The same rule applies to JSON error responses:

```go
// GOOD
json.NewEncoder(w).Encode(map[string]string{"error": "invalid request"})

// BAD -- leaks err internals via JSON
json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
```

```go
// GOOD
if err := authenticate(user, password); err != nil {
    log.Error("authentication failed",
        "username", user,
        "error", err,
        // NOTE: password is deliberately NOT logged
    )
    http.Error(w, "authentication failed", http.StatusUnauthorized)
    return
}

// BAD -- leaks the password in the error
http.Error(w, fmt.Sprintf("wrong password: %s", password), http.StatusUnauthorized)

// BAD -- leaks connection string with credentials
log.Printf("db error with conn %s: %v", connString, err)
```

**Secret-safe error wrapping pattern:**
```go
// Wrap errors with context but strip secrets
func dbError(operation string, err error) error {
    // Do NOT include connection strings, credentials, or raw query params
    return fmt.Errorf("database %s failed: %w", operation, err)
}
```

### CWE-306: Missing Authentication for Critical Function

**ALWAYS:**
- Require authentication for all endpoints that access, modify, or delete data.
- Use authentication middleware that runs before any handler logic.
- Protect administrative, configuration, and health-check endpoints that reveal sensitive data.

**NEVER:**
- Expose data-modifying endpoints without authentication.
- Rely on "security through obscurity" for internal endpoints.

### CWE-918: Server-Side Request Forgery (SSRF)

**ALWAYS:**
- Validate and restrict URLs that the server will fetch on behalf of users.
- Use an allowlist of permitted hostnames or IP ranges.
- Block requests to private/internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1, fc00::/7).
- Resolve DNS and validate the resolved IP before making the request.
- Set timeouts on HTTP clients making outbound requests.

```go
func isPrivateIP(ip net.IP) bool {
    privateRanges := []string{
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
        "192.168.0.0/16", "169.254.0.0/16",
    }
    for _, cidr := range privateRanges {
        _, network, _ := net.ParseCIDR(cidr)
        if network.Contains(ip) {
            return true
        }
    }
    return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
```

### CWE-770: Allocation of Resources Without Limits or Throttling

**ALWAYS:**
- Set timeouts on all servers: `ReadTimeout`, `WriteTimeout`, `IdleTimeout` on `http.Server`.
- Limit request body sizes with `http.MaxBytesReader`.
- Limit concurrent goroutines with semaphores or worker pools.
- Limit the size of data structures populated from external input (e.g. `io.LimitReader`).
- Set context deadlines/timeouts for long-running operations.
- Use rate limiting for public APIs.

```go
srv := &http.Server{
    Addr:         ":8080",
    ReadTimeout:  5 * time.Second,
    WriteTimeout: 10 * time.Second,
    IdleTimeout:  120 * time.Second,
    Handler:      mux,
}
```

---

## Mandatory Error Handling Rules

These rules apply to ALL generated Go code, regardless of which CWE is involved.

### 1. Always check errors

```go
// GOOD
f, err := os.Open(path)
if err != nil {
    return fmt.Errorf("opening file: %w", err)
}
defer f.Close()

// BAD -- discarded error
f, _ := os.Open(path)
```

### 2. Use error wrapping with context

```go
if err := db.Ping(); err != nil {
    return fmt.Errorf("checking database connectivity: %w", err)
}
```

### 3. Never include secrets in error messages

```go
// GOOD -- no secret material in the error
return fmt.Errorf("connecting to database at %s:%d: %w", host, port, err)

// BAD -- leaks password
return fmt.Errorf("connecting to %s with password %s: %w", dsn, password, err)
```

### 4. Use structured logging, never log secrets

```go
// GOOD
slog.Error("request failed",
    "method", r.Method,
    "path", r.URL.Path,
    "error", err,
)

// BAD -- leaks the authorisation token
slog.Error("auth failed", "token", r.Header.Get("Authorization"), "error", err)
```

### 5. Defer cleanup with error checking where possible

```go
f, err := os.Create(path)
if err != nil {
    return fmt.Errorf("creating file: %w", err)
}
defer func() {
    if cerr := f.Close(); cerr != nil {
        slog.Error("closing file", "path", path, "error", cerr)
    }
}()
```

---

## Mandatory Input Validation Rules

### For HTTP handlers

```go
func handler(w http.ResponseWriter, r *http.Request) {
    // 1. Limit request body size
    r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

    // 2. Check HTTP method
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // 3. Parse and validate input
    // 4. Authenticate and authorise
    // 5. Process request
    // 6. Return appropriate status codes
}
```

### For CLI tools

```go
func main() {
    // Validate all flags/arguments before use
    if *flagPath == "" {
        fmt.Fprintf(os.Stderr, "error: --path is required\n")
        os.Exit(1)
    }
    // Validate path is safe (no traversal, exists, correct permissions)
}
```

### For library functions

```go
// Validate parameters at the public API boundary
func ProcessData(input []byte, maxSize int) (Result, error) {
    if len(input) == 0 {
        return Result{}, errors.New("input must not be empty")
    }
    if len(input) > maxSize {
        return Result{}, fmt.Errorf("input size %d exceeds maximum %d", len(input), maxSize)
    }
    // ...
}
```

---

## Quick Checklist Before Returning Go Code

Before saving, committing or presenting any Go code to the user, verify:

- [ ] Code does NOT import `"unsafe"` or use any `unsafe` package functions
- [ ] Code does NOT use `reflect.SliceHeader` or `reflect.StringHeader`
- [ ] Code does NOT use `//go:linkname` directives
- [ ] All errors are checked (no `_` for error returns)
- [ ] Error messages contain NO passwords, tokens, API keys, or secrets
- [ ] `err.Error()` is NEVER passed directly into `http.Error()`, JSON responses, or any client-facing output
- [ ] All external input is validated (type, length, range, format)
- [ ] SQL queries use parameterised queries, not string concatenation
- [ ] HTML output uses `html/template`, not `text/template` or `fmt.Fprintf`
- [ ] File paths from user input are validated against a base directory
- [ ] OS commands use `exec.Command(name, arg1, arg2)`, not shell strings
- [ ] HTTP servers have timeouts configured
- [ ] Request body sizes are limited
- [ ] Pointers and interfaces are nil-checked before use
- [ ] Type assertions use the comma-ok pattern
- [ ] Maps are initialised before use
- [ ] Goroutines are bounded (worker pools, semaphores, or contexts)
- [ ] SSRF protections are in place for any user-controlled URL fetching
- [ ] Authorisation checks exist for every sensitive operation
- [ ] Authentication is required for all non-public endpoints
- [ ] File uploads validate content type, size, and use safe storage paths
- [ ] CSRF protection is present for state-changing web endpoints
- [ ] `encoding/gob` is never used with untrusted input
- [ ] JSON decoding uses `io.LimitReader` and validates decoded fields
