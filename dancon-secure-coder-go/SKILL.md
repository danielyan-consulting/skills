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

## Quick-Reference Rules

Scan this table first. Detailed rules and examples follow below.

| CWE | One-Line Rule |
|---------|---------------------------------------------------------------|
| CWE-79 | Use `html/template` only; never concatenate user input into HTML |
| CWE-89 | Use parameterised queries only; never string-build SQL |
| CWE-352 | Require CSRF tokens on all state-changing endpoints |
| CWE-862/863/284/639 | Derive identity from session; check ownership server-side on every operation |
| CWE-22 | `filepath.Abs` + `strings.HasPrefix` against base dir; never trust `filepath.Join` alone |
| CWE-78/77 | `exec.Command(name, arg1, arg2)` only; never pass a shell string |
| CWE-94 | Never let user input define template content or plugin paths |
| CWE-434 | Validate upload content with `http.DetectContentType`; allowlist MIME types |
| CWE-476 | Nil-check all pointers/interfaces; comma-ok all type assertions |
| CWE-502 | `io.LimitReader` + `DisallowUnknownFields`; decode into concrete structs; never `gob` from untrusted sources |
| CWE-20 | Validate type, length, range, format at the boundary; prefer allowlists |
| CWE-200 | Return generic errors to clients; log detail server-side; never expose `err.Error()` |
| CWE-306 | Authentication middleware on every non-public endpoint |
| CWE-918 | Allowlist target hosts; block private IPs; resolve DNS before fetching |
| CWE-770 | Set `http.Server` timeouts; `MaxBytesReader`; bound goroutines; use `crypto/rand` for secrets |

---

## Core Principles

1. **Validate all input** -- every function that accepts external data must validate it before use.
2. **Handle every error** -- never discard errors with `_`; always check and handle them.
3. **Never leak secrets in errors** -- error messages must never contain passwords, tokens, API keys, connection strings with credentials, or any secret material. Log sanitised context only.
4. **Defence in depth** -- apply multiple layers of protection; do not rely on a single check.
5. **Principle of least privilege** -- request only the permissions and access actually needed.
6. **Goroutine discipline** -- always bound goroutine creation with worker pools, semaphores, or context cancellation. Protect shared mutable state with `sync.Mutex`, `sync.RWMutex`, channels, or `sync/atomic`. Never rely on goroutine scheduling order for correctness.

---

## Prohibition of the `unsafe` Package and Related Escape Hatches

The `unsafe` package MUST NEVER be used in any generated Go code. This is the single authoritative statement of this prohibition -- it is absolute and has no exceptions.

**What is prohibited:**

- Importing `"unsafe"` in any form
- Using `unsafe.Pointer`, `unsafe.Sizeof`, `unsafe.Alignof`, `unsafe.Offsetof`, `unsafe.Slice`, or `unsafe.Add`
- Using `reflect.SliceHeader` or `reflect.StringHeader` (which require `unsafe` to be useful)
- Using `//go:linkname` directives
- Using `cgo` in ways that bypass Go's memory safety

**When the user requests `unsafe`:** Explain that this skill prohibits it and suggest safe alternatives using the standard library or well-maintained third-party packages. If no safe alternative exists, explain the limitation rather than generating unsafe code.

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
// GOOD -- html/template auto-escapes
tmpl := template.Must(template.ParseFiles("page.html"))
tmpl.Execute(w, data)

// BAD -- raw user input in HTML
fmt.Fprintf(w, "<h1>%s</h1>", userInput)
```

### CWE-89: SQL Injection

**ALWAYS:**
- Use parameterised queries with `?` or `$N` placeholders.
- Use `db.Query(query, args...)`, `db.Exec(query, args...)`, `db.QueryRow(query, args...)`.
- For dynamic identifiers (table/column names), use a strict allowlist.

**NEVER:**
- Build SQL strings with `fmt.Sprintf`, `+`, or `strings.Join` using user input.

```go
// GOOD -- parameterised
rows, err := db.Query("SELECT name FROM users WHERE id = $1", userID)

// BAD -- string concatenation
rows, err := db.Query("SELECT name FROM users WHERE id = " + userID)
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
userID := r.Context().Value(ctxUserID).(string)
order, err := db.GetOrder(r.Context(), orderID)
if err != nil {
    http.Error(w, "order not found", http.StatusNotFound)
    return
}
if order.UserID != userID {
    http.Error(w, "forbidden", http.StatusForbidden)
    return
}

// BAD -- trusting client-supplied user ID
clientUserID := r.URL.Query().Get("user_id")
order, _ := db.GetOrderForUser(r.Context(), clientUserID, orderID)
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
// GOOD -- resolve and confine to base directory
absBase, _ := filepath.Abs(baseDir)
joined := filepath.Join(absBase, filepath.Clean("/"+userPath))
absJoined, _ := filepath.Abs(joined)
if !strings.HasPrefix(absJoined, absBase+string(filepath.Separator)) && absJoined != absBase {
    return fmt.Errorf("path escapes base directory")
}

// BAD -- user input passed directly
f, err := os.Open(filepath.Join(baseDir, userPath))
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
// GOOD -- separate arguments
cmd := exec.Command("convert", inputFile, "-resize", "200x200", outputFile)

// BAD -- shell string with user input
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
// GOOD -- limit size, detect real content type, check allowlist
r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
file, _, err := r.FormFile("upload")
if err != nil {
    http.Error(w, "upload failed", http.StatusBadRequest)
    return
}
defer file.Close()
buf := make([]byte, 512)
n, _ := file.Read(buf)
contentType := http.DetectContentType(buf[:n])
allowed := map[string]bool{"image/png": true, "image/jpeg": true}
if !allowed[contentType] {
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
// GOOD -- comma-ok type assertion
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
// GOOD -- limited reader, strict decoding, post-decode validation
decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
decoder.DisallowUnknownFields()
var req CreateUserRequest
if err := decoder.Decode(&req); err != nil {
    http.Error(w, "invalid request body", http.StatusBadRequest)
    return
}
if err := req.Validate(); err != nil {
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
// GOOD -- length and character set validation
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

**NEVER pass `err.Error()` directly into HTTP responses.** The `err.Error()` string may contain internal details such as file paths, database error text, driver messages, stack frames, or wrapped context from deeper in the call chain -- none of which should be exposed to clients. Instead, return a fixed, generic message and log the real error server-side.

**NEVER include any of these in error messages, logs, or API responses:**
- Passwords or password hashes
- API keys, tokens, bearer tokens, JWTs
- Database connection strings containing credentials
- Private keys, certificates, or secret material
- Session identifiers in client-facing errors
- Full stack traces in production responses

```go
// GOOD -- generic message to client, detail logged server-side
if err := doSomething(); err != nil {
    slog.Error("operation failed", "error", err)
    http.Error(w, "internal server error", http.StatusInternalServerError)
    return
}

// BAD -- err.Error() can leak internal details to the client
http.Error(w, err.Error(), http.StatusInternalServerError)
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
// GOOD -- check resolved IP against private ranges before fetching
func isPrivateIP(ip net.IP) bool {
    privateRanges := []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}
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
- Use `crypto/rand` (not `math/rand`) for security-sensitive random values such as tokens, nonces, and session IDs.

```go
// GOOD -- all timeouts configured
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
slog.Error("request failed", "method", r.Method, "path", r.URL.Path, "error", err)

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

## Mandatory Checklist Before Returning Go Code

Before saving, committing or presenting any Go code to the user, verify every item below. **If any check fails, fix the issue and re-run the full checklist from the beginning before presenting the code.** Do not present code that has not passed a complete, clean run of this checklist.

**`unsafe` prohibition:**
- [ ] Code does NOT import `"unsafe"`, use any `unsafe` package function, use `reflect.SliceHeader`/`reflect.StringHeader`, or contain `//go:linkname` directives

**Error handling and secrets:**
- [ ] All errors are checked (no `_` for error returns)
- [ ] Error messages contain NO passwords, tokens, API keys, or secrets
- [ ] `err.Error()` is NEVER passed directly into `http.Error()`, JSON responses, or any client-facing output

**Input validation:**
- [ ] All external input is validated (type, length, range, format)
- [ ] SQL queries use parameterised queries, not string concatenation
- [ ] HTML output uses `html/template`, not `text/template` or `fmt.Fprintf`
- [ ] File paths from user input are validated against a base directory
- [ ] OS commands use `exec.Command(name, arg1, arg2)`, not shell strings

**Go-specific runtime safety:**
- [ ] HTTP servers have timeouts configured (`ReadTimeout`, `WriteTimeout`, `IdleTimeout`)
- [ ] Request body sizes are limited
- [ ] Pointers and interfaces are nil-checked before use
- [ ] Type assertions use the comma-ok pattern
- [ ] Maps are initialised before use
- [ ] Goroutines are bounded (worker pools, semaphores, or contexts)
- [ ] Shared mutable state accessed by multiple goroutines is protected by `sync.Mutex`, channels, or `sync/atomic`
- [ ] Security-sensitive random values use `crypto/rand`, not `math/rand`

**Application-level security:**
- [ ] SSRF protections are in place for any user-controlled URL fetching
- [ ] Authorisation checks exist for every sensitive operation
- [ ] Authentication is required for all non-public endpoints
- [ ] File uploads validate content type, size, and use safe storage paths
- [ ] CSRF protection is present for state-changing web endpoints
- [ ] `encoding/gob` is never used with untrusted input
- [ ] JSON decoding uses `io.LimitReader` and validates decoded fields
