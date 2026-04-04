# Error Handling and Input Validation Patterns

Mandatory patterns for all generated Go code. These are Go-idiomatic conventions -- consult this file when you need to verify the correct pattern.

---

## Error Handling

**1. Always check errors** -- no `_` for error returns.

```go
f, err := os.Open(path)
if err != nil {
    return fmt.Errorf("opening file: %w", err)
}
defer f.Close()
```

**2. Wrap with context** using `%w`.

```go
if err := db.Ping(); err != nil {
    return fmt.Errorf("checking database connectivity: %w", err)
}
```

**3. No secrets in errors** -- no passwords, tokens, keys, or connection strings.

```go
// GOOD
return fmt.Errorf("connecting to database at %s:%d: %w", host, port, err)

// BAD
return fmt.Errorf("connecting to %s with password %s: %w", dsn, password, err)
```

**4. Structured logging, no secrets** -- use `slog`; never log auth headers, tokens, or credentials.

**5. Defer cleanup with error checking.**

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

## Input Validation

**HTTP handlers:** Limit body (`MaxBytesReader`), check method, parse and validate, authenticate and authorise, then process.

**CLI tools:** Validate all flags/arguments before use; verify paths are safe.

**Library functions:** Validate at the public API boundary -- check emptiness, size bounds, and format before processing.
