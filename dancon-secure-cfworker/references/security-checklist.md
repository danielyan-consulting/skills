# Security Checklist: OWASP Top 10 (2025) + CWE Top 25 (2025) for Cloudflare Workers

This reference maps every item from the OWASP Top 10 (2025 edition) and the CWE Top 25 (2025 edition) to concrete, actionable mitigations in the Cloudflare Workers TypeScript context. Consult this while generating code to ensure nothing is missed.

---

## Table of Contents

1. [OWASP Top 10 (2025)](#owasp-top-10-2025)
2. [CWE Top 25 (2025)](#cwe-top-25-2025)
3. [Workers-Specific Security Patterns](#workers-specific-security-patterns)
4. [Security Header Reference](#security-header-reference)
5. [Cryptographic API Quick Reference](#cryptographic-api-quick-reference)

---

## OWASP Top 10 (2025)

### A01:2025 -- Broken Access Control

**What it covers:** IDOR, privilege escalation, CORS misconfiguration, SSRF (absorbed from A10:2021), path traversal, metadata manipulation, forced browsing.

**Workers mitigations:**

- Authenticate every non-public request. Extract and verify credentials (JWT, API key, session) in a middleware function that runs before any business logic.
- Perform resource-level authorisation checks. After identifying the user, verify they have permission to access the specific resource (not just the route).
- Validate and restrict outbound URLs to prevent SSRF. Maintain an allowlist of permitted external hosts. Never let user input directly control `fetch()` target URLs.
- Set CORS headers explicitly per-origin. Never use `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`.
- For path-based routing, normalise and validate path segments. Reject `..`, encoded traversal sequences (`%2e%2e`), and null bytes.
- Return `403 Forbidden` (not `404 Not Found`) when a user attempts to access a resource they are not authorised for, unless revealing existence is itself a risk, in which case return `404`.

**Relevant CWEs:** CWE-22, CWE-284, CWE-285, CWE-352, CWE-639, CWE-770, CWE-862, CWE-863, CWE-918

```typescript
// SSRF prevention: allowlist outbound hosts
const ALLOWED_HOSTS = new Set(["api.stripe.com", "hooks.slack.com"]);

async function safeFetch(url: string, init?: RequestInit): Promise<Response> {
  const parsed = new URL(url);
  if (!ALLOWED_HOSTS.has(parsed.hostname)) {
    throw new HttpError(400, "Outbound request to disallowed host");
  }
  // Prevent internal/metadata access
  if (parsed.hostname === "localhost" || parsed.hostname.endsWith(".internal")) {
    throw new HttpError(400, "Outbound request to disallowed host");
  }
  return fetch(url, init);
}
```

### A02:2025 -- Security Misconfiguration

**What it covers:** Default credentials, unnecessary features enabled, overly permissive cloud settings, missing security headers, verbose error messages, outdated software.

**Workers mitigations:**

- Set `compatibility_date` to the most recent date to pick up runtime security fixes.
- Enable `nodejs_compat` for access to secure Node.js built-ins.
- Enable `observability` in wrangler.jsonc for production logging.
- Remove any debug/test routes before deploying to production.
- Never expose raw error stacks or internal paths in responses.
- Store all secrets via `wrangler secret put`. Never put them in `wrangler.jsonc` or source code.
- Add `.dev.vars` to `.gitignore`.
- Set security headers on every response (see Security Header Reference below).

```jsonc
// wrangler.jsonc -- secure baseline configuration
{
  "name": "my-secure-worker",
  "main": "src/index.ts",
  "compatibility_date": "2026-03-01",
  "compatibility_flags": ["nodejs_compat"],
  "observability": {
    "enabled": true
  }
  // Secrets stored via `wrangler secret put`, NOT here
}
```

### A03:2025 -- Software Supply Chain Failures

**What it covers:** Vulnerable or malicious dependencies, compromised build pipelines, dependency confusion, typosquatting.

**Workers mitigations:**

- Minimise dependencies. The Workers runtime provides Web Crypto, Streams, URL parsing, and other APIs natively. Avoid importing libraries for things the runtime already does.
- Pin exact dependency versions in `package.json` (no `^` or `~` ranges for production).
- Run `npm audit` (or equivalent) before every deployment.
- Use `package-lock.json` and commit it to source control.
- Prefer well-maintained, widely-used libraries (e.g. `zod` for validation, `hono` or `itty-router` for routing).
- Review new dependencies before adding them. Check download counts, maintenance status, and known vulnerabilities.

### A04:2025 -- Cryptographic Failures

**What it covers:** Missing or weak encryption, key exposure, insufficient hashing, cleartext transmission.

**Workers mitigations:**

- Use the Web Crypto API (`crypto.subtle`) for all cryptographic operations.
- Use `crypto.randomUUID()` for identifiers and `crypto.getRandomValues()` for random bytes.
- Never use `Math.random()` for tokens, IDs, or any security purpose.
- For password hashing, use PBKDF2 with SHA-256 and a high iteration count (at least 600,000), or Argon2 if available via a WASM library.
- For JWT signing, use ECDSA (P-256) or HMAC-SHA256 at minimum.
- For encryption, use AES-GCM with 256-bit keys and unique IVs per encryption.
- Never log or expose cryptographic keys, even partially.
- Never display real or generated secrets, tokens, passwords, or key material in code output, comments, or responses. Use placeholder values or `env` references instead.
- Cloudflare handles TLS at the edge, but ensure your Worker does not downgrade by redirecting to or fetching from HTTP URLs.

### A05:2025 -- Injection

**What it covers:** SQL injection, header injection, XSS.

**Workers mitigations:**

- Use parameterised queries for D1 (always `.bind()`, never string interpolation).
- Validate and sanitise all user input with strict schemas before use.
- When generating HTML, use context-aware output encoding (HTML entity encoding for content, attribute encoding for attributes, JavaScript encoding for script contexts).
- When setting response headers derived from user input, strip newlines and control characters to prevent header injection.
- Never use `eval()`, `new Function()`, or `setTimeout`/`setInterval` with string arguments.
- For KV keys derived from user input, validate key format and reject special characters.

```typescript
// Header injection prevention
function safeSetHeader(headers: Headers, name: string, value: string): void {
  const sanitised = value.replace(/[\r\n\x00]/g, "");
  headers.set(name, sanitised);
}

// HTML encoding for output
function htmlEncode(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}
```

### A06:2025 -- Insecure Design

**What it covers:** Missing threat modelling, insecure business logic, lack of rate limiting, missing abuse controls.

**Workers mitigations:**

- Implement rate limiting on sensitive endpoints (login, registration, password reset). Use Durable Objects for distributed rate limiting.
- Design APIs with the principle of least privilege: only return data the authenticated user is entitled to see.
- Use idempotency keys for state-changing operations to prevent replay attacks.
- Validate business logic invariants server-side. Never trust client-side enforcement.
- Consider abuse scenarios: what happens if someone calls this endpoint 10,000 times? What if they supply the maximum allowed size for every field?

```typescript
// Rate limiting with Durable Objects
export class RateLimiter implements DurableObject {
  private requests: number[] = [];

  async fetch(request: Request): Promise<Response> {
    const now = Date.now();
    const windowMs = 60_000; // 1 minute
    const maxRequests = 60;

    // Remove expired entries
    this.requests = this.requests.filter((t) => now - t < windowMs);

    if (this.requests.length >= maxRequests) {
      return new Response(JSON.stringify({ error: "Rate limit exceeded" }), {
        status: 429,
        headers: {
          "Retry-After": "60",
          "Content-Type": "application/json",
        },
      });
    }

    this.requests.push(now);
    return new Response("OK", { status: 200 });
  }
}
```

### A07:2025 -- Identification and Authentication Failures

**What it covers:** Credential stuffing, brute force, weak passwords, broken session management, missing MFA.

**Workers mitigations:**

- Verify JWT signatures cryptographically. Never trust a JWT payload without signature verification.
- Use timing-safe comparison for API keys and tokens (see `crypto.subtle.timingSafeEqual`).
- Rate limit authentication endpoints.
- Set appropriate token expiry times. Short-lived access tokens (15 minutes) with longer-lived refresh tokens.
- Never expose tokens in URLs or query parameters.
- Invalidate sessions/tokens on logout and password change.

### A08:2025 -- Software and Data Integrity Failures

**What it covers:** Deserialisation attacks, unsigned updates, CI/CD pipeline compromise, integrity verification failures.

**Workers mitigations:**

- Validate webhook signatures (HMAC-SHA256) before processing payloads.
- When accepting serialised data (JSON), parse with `JSON.parse()` and then validate the resulting structure with a schema. Never use custom deserialisation.
- Verify integrity of data retrieved from KV or R2 if tamper-resistance is required (store and check HMAC alongside data).

```typescript
// Webhook signature verification
async function verifyWebhookSignature(
  payload: string,
  signature: string,
  secret: string
): Promise<boolean> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const expected = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
  const expectedHex = [...new Uint8Array(expected)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  // Timing-safe comparison
  const sigBytes = encoder.encode(signature);
  const expBytes = encoder.encode(expectedHex);
  if (sigBytes.byteLength !== expBytes.byteLength) return false;
  return crypto.subtle.timingSafeEqual(sigBytes, expBytes);
}
```

### A09:2025 -- Security Logging and Alerting Failures

**What it covers:** Missing audit logs, logs not monitored, insufficient alerting, log injection.

**Workers mitigations:**

- Log all authentication attempts (success and failure) with sanitised context.
- Log authorisation failures.
- Use structured JSON logging for machine parseability.
- Sanitise user-controlled data before including it in log messages (remove control characters, truncate long values).
- Enable `observability` in `wrangler.jsonc`.
- Integrate with external logging (e.g. Logpush) for persistent, searchable logs.
- Never log secrets, tokens, passwords, or full credit card numbers.
- Never output real or generated secret values in code examples, inline comments, or chat responses. Always use placeholders like `"YOUR_SECRET_HERE"` or environment variable references.

```typescript
// PII-safe logging
function auditLog(event: string, context: Record<string, unknown>): void {
  const safe = { ...context };
  // Redact sensitive fields
  if (safe.email && typeof safe.email === "string") {
    safe.email = safe.email.replace(/(.{2}).*(@.*)/, "$1***$2");
  }
  delete safe.password;
  delete safe.token;
  delete safe.apiKey;

  console.log(JSON.stringify({
    event,
    ...safe,
    ts: new Date().toISOString(),
  }));
}
```

### A10:2025 -- Mishandling of Exceptional Conditions

**What it covers:** Improper error handling, failing open, unhandled exceptions, logic errors under abnormal conditions.

**Workers mitigations:**

- Wrap the entire `fetch` handler in a try/catch. The outer catch must return a safe error response, never an unhandled rejection.
- Distinguish between expected errors (validation failures, auth failures) and unexpected errors (runtime exceptions). Return appropriate status codes for each.
- Never use `passThroughOnException()` unless you fully understand it forwards raw requests to origin on failure, potentially bypassing security logic.
- Handle all promise rejections. Use the `no-floating-promises` ESLint rule.
- Fail closed: if an authorisation check throws, deny access (do not default to allow).
- Validate assumptions: if a required environment variable or binding is missing, fail immediately at startup with a clear message rather than producing undefined behaviour later.

```typescript
// Fail-closed error handling
async function authorise(request: Request, env: Env): Promise<User> {
  try {
    return await verifyAndGetUser(request, env);
  } catch (err) {
    // Fail closed: any error in auth means deny
    throw new HttpError(401, "Authentication failed");
  }
}
```

---

## CWE Top 25 (2025)

Below are the CWE Top 25 (2025) items relevant to Cloudflare Workers, with Workers-specific mitigations. Memory-safety weaknesses (buffer overflows, out-of-bounds read/write, use-after-free, null pointer dereference) and OS-level weaknesses (OS command injection, command injection) are omitted as they do not apply to the Workers TypeScript runtime. Items already covered in depth by an OWASP category above are noted with cross-references.

| Rank | CWE | Name | Workers Mitigation | OWASP Cross-Ref |
|------|------|------|---------------------|-----------------|
| 1 | CWE-79 | Cross-site Scripting (XSS) | Context-aware output encoding when generating HTML. Set `Content-Security-Policy` headers. Use `X-Content-Type-Options: nosniff`. | A05 |
| 2 | CWE-89 | SQL Injection | Always use D1 parameterised queries (`.bind()`). Never interpolate user input into SQL strings. | A05 |
| 3 | CWE-352 | Cross-site Request Forgery (CSRF) | Use anti-CSRF tokens for state-changing operations. Verify `Origin` and `Referer` headers. Use `SameSite=Strict` on cookies. | A01 |
| 4 | CWE-862 | Missing Authorisation | Every endpoint with side effects or sensitive data must have explicit authorisation checks. | A01 |
| 5 | CWE-22 | Path Traversal | Validate and sanitise path segments. Reject `..`, encoded variants, and null bytes. Never use user input directly in KV/R2 key construction without validation. | A01 |
| 6 | CWE-94 | Improper Control of Code Generation | Never use `eval()`, `new Function()`, or dynamically construct code from user input. | A05 |
| 7 | CWE-434 | Unrestricted Upload of File with Dangerous Type | Validate file type (magic bytes, not just extension or Content-Type header). Enforce size limits. Store in R2 with randomised keys, never serve directly with original filename. | A01, A05 |
| 8 | CWE-502 | Deserialisation of Untrusted Data | Parse JSON with `JSON.parse()`, then validate with a schema. Never use custom deserialisation or prototype-polluting parsers. | A08 |
| 9 | CWE-863 | Incorrect Authorisation | Verify authorisation at the resource level, not just the route level. Check ownership, not just authentication. | A01 |
| 10 | CWE-20 | Improper Input Validation | Validate all inputs with strict schemas (type, length, format, range). Reject unexpected fields. | A05 |
| 11 | CWE-284 | Improper Access Control | Enforce access control on every request. Combine authentication and authorisation checks. Never rely on client-side enforcement or hidden URLs for protection. | A01 |
| 12 | CWE-200 | Exposure of Sensitive Information | Never return internal errors, stack traces, database errors, or file paths in responses. Redact PII from logs. | A09, A10 |
| 13 | CWE-306 | Missing Authentication for Critical Function | Every endpoint that reads, creates, modifies, or deletes data must require authentication unless explicitly designed as public. | A07 |
| 14 | CWE-918 | Server-side Request Forgery (SSRF) | Validate outbound URLs against an allowlist. Block requests to internal/metadata IPs (169.254.x.x, 10.x.x.x, localhost). | A01 |
| 15 | CWE-639 | Authorisation Bypass Through User-Controlled Key | Never use user-supplied identifiers (e.g. `?userId=123`) as the sole basis for authorisation. Always verify the authenticated user's identity matches or has permission for the requested resource. | A01 |
| 16 | CWE-770 | Allocation of Resources Without Limits or Throttling | Enforce request body size limits. Stream large payloads. Set timeouts on external fetches. Rate limit endpoints using Durable Objects. Cap KV/R2 write sizes. | A06, A10 |

---

## Workers-Specific Security Patterns

### Isolate Reuse Awareness

Workers reuse V8 isolates. This means module-level variables persist across requests to the same isolate. This is a data leakage vector.

**Rules:**
- Never store request-scoped data in module-level variables.
- If you must use module-level caches (e.g. for compiled schemas), ensure they contain no user-specific data.
- Use `Map` or `WeakMap` keyed by request-specific identifiers if per-request caching is needed within a request lifecycle.

### Binding Security

- Access bindings exclusively through the `env` parameter, never through global variables.
- Generate binding types with `wrangler types` rather than hand-writing Env interfaces.
- Treat bindings as capabilities: only declare bindings the Worker actually needs.

### Timeout and Abort Patterns

```typescript
// Fetch with timeout
async function fetchWithTimeout(
  url: string,
  init: RequestInit = {},
  timeoutMs: number = 5000
): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}
```

### Content-Type Validation

```typescript
function requireContentType(
  request: Request,
  expected: string
): void {
  const contentType = request.headers.get("Content-Type") ?? "";
  if (!contentType.includes(expected)) {
    throw new HttpError(
      415,
      `Unsupported Media Type: expected ${expected}`
    );
  }
}
```

---

## Security Header Reference

Apply these headers to every response. Adjust values based on application needs, but never weaken them without a specific reason.

| Header | Value | Purpose |
|--------|-------|---------|
| `Content-Type` | Set explicitly per response | Prevents MIME sniffing attacks (CWE-79) |
| `X-Content-Type-Options` | `nosniff` | Prevents browsers from MIME-sniffing (CWE-79) |
| `X-Frame-Options` | `DENY` | Prevents clickjacking (CWE-1021) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controls referrer leakage (CWE-200) |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Restricts browser features |
| `Cache-Control` | `no-store` for sensitive data | Prevents caching of sensitive responses (CWE-524) |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Enforces HTTPS (CWE-319) |
| `Content-Security-Policy` | Application-specific | Mitigates XSS (CWE-79) |

---

## Cryptographic API Quick Reference

### Generate a random UUID
```typescript
const id = crypto.randomUUID();
```

### Generate random bytes
```typescript
const bytes = new Uint8Array(32);
crypto.getRandomValues(bytes);
```

### HMAC-SHA256 signing
```typescript
const encoder = new TextEncoder();
const key = await crypto.subtle.importKey(
  "raw",
  encoder.encode(secret),
  { name: "HMAC", hash: "SHA-256" },
  false,
  ["sign", "verify"]
);
const signature = await crypto.subtle.sign(
  "HMAC",
  key,
  encoder.encode(data)
);
```

### AES-GCM encryption
```typescript
const key = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  true,
  ["encrypt", "decrypt"]
);
const iv = crypto.getRandomValues(new Uint8Array(12)); // Unique per encryption
const ciphertext = await crypto.subtle.encrypt(
  { name: "AES-GCM", iv },
  key,
  encoder.encode(plaintext)
);
// Store iv alongside ciphertext -- it is not secret
```

### Timing-safe comparison
```typescript
const a = new TextEncoder().encode(valueA);
const b = new TextEncoder().encode(valueB);
// Only works if same length -- hash first if variable length
const equal = crypto.subtle.timingSafeEqual(a, b);
```

### JWT verification (HMAC-SHA256)
```typescript
async function verifyJwt(
  token: string,
  secret: string
): Promise<Record<string, unknown>> {
  const [headerB64, payloadB64, signatureB64] = token.split(".");
  if (!headerB64 || !payloadB64 || !signatureB64) {
    throw new HttpError(401, "Malformed token");
  }

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const data = encoder.encode(`${headerB64}.${payloadB64}`);
  const signature = base64UrlDecode(signatureB64);

  const valid = await crypto.subtle.verify("HMAC", key, signature, data);
  if (!valid) {
    throw new HttpError(401, "Invalid token signature");
  }

  const payload = JSON.parse(atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/")));

  // Check expiry
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
    throw new HttpError(401, "Token expired");
  }

  return payload;
}

function base64UrlDecode(str: string): ArrayBuffer {
  const padded = str + "=".repeat((4 - (str.length % 4)) % 4);
  const binary = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
```
