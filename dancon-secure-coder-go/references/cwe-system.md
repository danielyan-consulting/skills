# CWE Reference: System-Level and Data-Handling Vulnerabilities

Go-specific rules for system, data, and runtime CWEs. One example per CWE.

---

## CWE-22: Path Traversal

**ALWAYS:** `filepath.Clean` then `filepath.Abs`, then `strings.HasPrefix` against the absolute base directory.

**NEVER:** User input directly to `os.Open`/`os.ReadFile`/`os.Create`/`http.ServeFile`; `filepath.Join` alone does not prevent traversal.

```go
// GOOD
absBase, _ := filepath.Abs(baseDir)
joined := filepath.Join(absBase, filepath.Clean("/"+userPath))
absJoined, _ := filepath.Abs(joined)
if !strings.HasPrefix(absJoined, absBase+string(filepath.Separator)) && absJoined != absBase {
    return fmt.Errorf("path escapes base directory")
}

// BAD
f, err := os.Open(filepath.Join(baseDir, userPath))
```

---

## CWE-78/77: Command Injection

**ALWAYS:** `exec.Command(name, arg1, arg2, ...)` with separate arguments; allowlist-validate all args; prefer stdlib over shelling out.

**NEVER:** `exec.Command("sh", "-c", userInput)`; concatenating user input into command strings.

```go
// GOOD
cmd := exec.Command("convert", inputFile, "-resize", "200x200", outputFile)

// BAD
cmd := exec.Command("sh", "-c", "convert "+userInput+" -resize 200x200 out.png")
```

---

## CWE-94: Code Injection

**ALWAYS:** Treat template strings as code; never allow user input to define template content or plugin paths.

**NEVER:** Parse user-supplied strings as Go templates; `plugin.Open` with user-controlled paths.

---

## CWE-476: Nil Pointer Dereference

**ALWAYS:** Nil-check pointers and interfaces before dereferencing; check error before using the value; comma-ok type assertions; initialise maps with `make`.

**NEVER:** Bare type assertions (`val := x.(Type)`); assume non-nil returns without checking.

```go
// GOOD
val, ok := x.(string)
if !ok {
    return fmt.Errorf("unexpected type: %T", x)
}

// BAD
val := x.(string)
```

---

## CWE-502: Deserialisation of Untrusted Data

**ALWAYS:** `io.LimitReader` before decoding; decode into concrete structs; `DisallowUnknownFields()` on `json.Decoder`; validate fields after decode.

**NEVER:** `encoding/gob` from untrusted sources; unlimited input; decode into `interface{}`.

```go
// GOOD
decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
decoder.DisallowUnknownFields()
var req CreateUserRequest
if err := decoder.Decode(&req); err != nil {
    http.Error(w, "invalid request body", http.StatusBadRequest)
    return
}
if err := req.Validate(); err != nil {
    slog.Warn("validation failed", "error", err)
    http.Error(w, "invalid request data", http.StatusUnprocessableEntity)
    return
}
```

---

## CWE-20: Input Validation

**ALWAYS:** Validate type, length, range, format at the boundary; allowlists over denylists; validate early.

```go
// GOOD
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

---

## CWE-200: Information Exposure

**ALWAYS:** Generic error messages to clients; detailed errors logged server-side with `slog`; strip stack traces in production.

**NEVER:** `err.Error()` in `http.Error()`, JSON responses, or any client-facing output. Never log passwords, tokens, keys, connection strings, or session IDs.

```go
// GOOD
if err := doSomething(); err != nil {
    slog.Error("operation failed", "error", err)
    http.Error(w, "internal server error", http.StatusInternalServerError)
    return
}

// BAD
http.Error(w, err.Error(), http.StatusInternalServerError)
```

---

## CWE-770: Resource Exhaustion

**ALWAYS:** `http.Server` timeouts (`ReadTimeout`, `WriteTimeout`, `IdleTimeout`); `http.MaxBytesReader`; goroutine bounds (semaphores, worker pools); `io.LimitReader` for external data; context deadlines; rate limiting; `crypto/rand` for security-sensitive randomness.

```go
// GOOD
srv := &http.Server{
    Addr:         ":8080",
    ReadTimeout:  5 * time.Second,
    WriteTimeout: 10 * time.Second,
    IdleTimeout:  120 * time.Second,
    Handler:      mux,
}
```
