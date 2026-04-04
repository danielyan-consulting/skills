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

# Secure Go Code Generator -- CWE Top 25 2025

By Danielyan Consulting: https://danielyan.consulting

Mandatory for ALL Go code generation. Apply these rules before writing any Go code.

## Quick-Reference Rules

This table is the primary lookup. For edge cases or unfamiliar CWEs, read the relevant reference file.

| CWE | Rule | Detail |
|---------|---------------------------------------------------------------|--------|
| CWE-79 | `html/template` only; never concatenate user input into HTML | [cwe-web.md] |
| CWE-89 | Parameterised queries only; never string-build SQL | [cwe-web.md] |
| CWE-352 | CSRF tokens on all state-changing endpoints | [cwe-web.md] |
| CWE-862/863/284/639 | Derive identity from session; check ownership server-side | [cwe-web.md] |
| CWE-306 | Authentication middleware on every non-public endpoint | [cwe-web.md] |
| CWE-434 | `http.DetectContentType` + MIME allowlist; limit size | [cwe-web.md] |
| CWE-918 | Allowlist target hosts; block private IPs; resolve DNS first | [cwe-web.md] |
| CWE-22 | `filepath.Abs` + `strings.HasPrefix` against base dir | [cwe-system.md] |
| CWE-78/77 | `exec.Command(name, arg1, arg2)`; never shell strings | [cwe-system.md] |
| CWE-94 | Never let user input define template content or plugin paths | [cwe-system.md] |
| CWE-476 | Nil-check pointers/interfaces; comma-ok all type assertions | [cwe-system.md] |
| CWE-502 | `io.LimitReader` + `DisallowUnknownFields`; concrete structs; no `gob` from untrusted | [cwe-system.md] |
| CWE-20 | Validate type, length, range, format at boundary; allowlists | [cwe-system.md] |
| CWE-200 | Generic errors to clients; log detail server-side; never expose `err.Error()` | [cwe-system.md] |
| CWE-770 | `http.Server` timeouts; `MaxBytesReader`; bound goroutines; `crypto/rand` for secrets | [cwe-system.md] |

## Core Principles

1. **Validate all input** at the boundary before use.
2. **Handle every error** -- no `_` for error returns.
3. **Never leak secrets in errors** -- no passwords, tokens, keys, or connection strings in error messages or logs.
4. **Defence in depth** -- multiple layers; never a single check.
5. **Least privilege** -- request only what is needed.
6. **Goroutine discipline** -- bound creation (worker pools, semaphores, context cancellation); protect shared state (`sync.Mutex`, `sync.RWMutex`, channels, `sync/atomic`); never rely on scheduling order.

## `unsafe` Prohibition

The `unsafe` package must never appear in generated Go code. This is absolute and has no exceptions.

Prohibited: importing `"unsafe"`; any `unsafe.*` function; `reflect.SliceHeader`/`reflect.StringHeader`; `//go:linkname` directives; `cgo` that bypasses memory safety.

If the user requests `unsafe`, explain this prohibition and suggest safe alternatives. If none exist, explain the limitation rather than generating unsafe code.

## Reference Files

Read these when the quick-reference table is insufficient for the CWE at hand:

| File | Contents |
|------|----------|
| `references/cwe-web.md` | CWE-79, 89, 352, 862/863/284/639, 306, 434, 918: web-facing vulnerabilities with Go-idiomatic ALWAYS/NEVER rules and one example each |
| `references/cwe-system.md` | CWE-22, 78/77, 94, 476, 502, 20, 200, 770: system-level and data-handling vulnerabilities with Go-idiomatic ALWAYS/NEVER rules and one example each |
| `references/error-and-input.md` | Mandatory error handling rules (wrapping, secrets, logging, cleanup) and input validation patterns (HTTP handlers, CLI, libraries) |

## Mandatory Checklist

Before presenting any Go code, verify every applicable item. **If any check fails, fix the issue and re-run the full checklist before presenting code.**

**`unsafe`:**
- [ ] No `"unsafe"` import, no `unsafe.*` functions, no `reflect.SliceHeader`/`reflect.StringHeader`, no `//go:linkname`

**Errors and secrets:**
- [ ] All errors checked (no `_`)
- [ ] No secrets in error messages or logs
- [ ] `err.Error()` never in client-facing output (`http.Error`, JSON responses)

**Input validation:**
- [ ] External input validated (type, length, range, format)
- [ ] SQL uses parameterised queries
- [ ] HTML uses `html/template`
- [ ] File paths confined to base directory
- [ ] OS commands use separate args, not shell strings

**Go runtime safety:**
- [ ] `http.Server` has `ReadTimeout`, `WriteTimeout`, `IdleTimeout`
- [ ] Request bodies limited (`MaxBytesReader`)
- [ ] Pointers/interfaces nil-checked
- [ ] Type assertions use comma-ok
- [ ] Maps initialised before use
- [ ] Goroutines bounded; shared state synchronised
- [ ] `crypto/rand` for security-sensitive randomness

**Application security:**
- [ ] SSRF protections on user-controlled URL fetching
- [ ] Authorisation checked on every sensitive operation
- [ ] Authentication on all non-public endpoints
- [ ] File uploads: content-type validated, size limited, safe storage paths
- [ ] CSRF tokens on state-changing web endpoints
- [ ] No `encoding/gob` from untrusted input
- [ ] JSON decoding uses `io.LimitReader` and validates fields
