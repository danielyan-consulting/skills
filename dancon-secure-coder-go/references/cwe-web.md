# CWE Reference: Web-Facing Vulnerabilities

Go-specific rules for web-facing CWEs. One example per CWE -- the most Go-idiomatic pattern.

---

## CWE-79: XSS

**ALWAYS:** `html/template` with auto-escaping; explicit `Content-Type` headers; `X-Content-Type-Options: nosniff` and `Content-Security-Policy` headers. Do not bypass escaping with `template.HTML()` unless provably safe with a comment explaining why.

**NEVER:** `text/template` for HTML; `fmt.Fprintf` or string concatenation with user input into HTML; writing user data directly to `http.ResponseWriter`.

```go
// GOOD
tmpl := template.Must(template.ParseFiles("page.html"))
tmpl.Execute(w, data)

// BAD
fmt.Fprintf(w, "<h1>%s</h1>", userInput)
```

---

## CWE-89: SQL Injection

**ALWAYS:** Parameterised queries (`$1`/`?` placeholders) via `db.Query`, `db.Exec`, `db.QueryRow`. For dynamic identifiers (table/column names), strict allowlist only.

**NEVER:** `fmt.Sprintf`, `+`, or `strings.Join` with user input in SQL.

```go
// GOOD
rows, err := db.Query("SELECT name FROM users WHERE id = $1", userID)

// BAD
rows, err := db.Query("SELECT name FROM users WHERE id = " + userID)
```

---

## CWE-352: CSRF

**ALWAYS:** CSRF library (`gorilla/csrf`, `justinas/nosurf`) on state-changing endpoints; `SameSite=Lax` or `Strict` on session cookies; verify `Origin`/`Referer` as additional layer.

**NEVER:** Cookies-only authentication for state-changing requests without CSRF tokens.

---

## CWE-862/863/284/639: Authorisation and Access Control

**ALWAYS:** Check authorisation on every endpoint and operation. Derive user identity from the authenticated session/token, never from request parameters alone. Compare ownership server-side. Use middleware for role/permission checks.

**NEVER:** Trust client-supplied user IDs, role claims, or resource IDs without server-side verification.

```go
// GOOD -- identity from context, ownership checked
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

// BAD -- trusting client-supplied ID
clientUserID := r.URL.Query().Get("user_id")
order, _ := db.GetOrderForUser(r.Context(), clientUserID, orderID)
```

---

## CWE-306: Missing Authentication

**ALWAYS:** Authentication middleware before handler logic on all endpoints that access, modify, or delete data. Protect admin and config endpoints.

**NEVER:** Data-modifying endpoints without authentication; security through obscurity.

---

## CWE-434: Unrestricted File Upload

**ALWAYS:** `http.MaxBytesReader` for size; `http.DetectContentType` on content bytes (not extension or header); MIME allowlist; generated filenames stored outside web root.

```go
// GOOD
r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
file, _, err := r.FormFile("upload")
if err != nil {
    http.Error(w, "upload failed", http.StatusBadRequest)
    return
}
defer file.Close()
buf := make([]byte, 512)
n, _ := file.Read(buf)
if !allowedTypes[http.DetectContentType(buf[:n])] {
    http.Error(w, "file type not allowed", http.StatusUnsupportedMediaType)
    return
}
```

---

## CWE-918: SSRF

**ALWAYS:** Allowlist permitted hostnames/IPs; block private ranges (127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1, fc00::/7); resolve DNS and validate IP before request; timeouts on outbound HTTP clients.

```go
// GOOD
func isPrivateIP(ip net.IP) bool {
    for _, cidr := range []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"} {
        _, network, _ := net.ParseCIDR(cidr)
        if network.Contains(ip) {
            return true
        }
    }
    return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
```
