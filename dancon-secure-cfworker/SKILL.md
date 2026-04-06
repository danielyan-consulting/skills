---
name: dancon-secure-cfworker
description: Generate secure Cloudflare Worker code in TypeScript that avoids all weaknesses covered by OWASP Top 10 (2025) and CWE Top 25 (2025). Use this skill whenever the user asks to create, write, scaffold, or generate a Cloudflare Worker, CF Worker, edge function, or serverless function on Cloudflare. Also trigger when the user asks to build a secure API, secure endpoint, secure webhook handler, or any TypeScript code targeting the Workers runtime. Trigger even for casual requests like "make me a worker that does X", "CF worker for Y", "edge API for Z", or "I need a Cloudflare function". If the user mentions Cloudflare Workers and security together, or asks for a hardened/secure worker, this skill is essential. Always use this skill over generic code generation when the target is Cloudflare Workers.
---

# Secure Cloudflare Worker Generator

This skill generates production-grade, security-hardened Cloudflare Worker code in TypeScript. Every piece of generated code systematically addresses the weaknesses catalogued in the OWASP Top 10 (2025) and CWE Top 25 (2025), applying defence-in-depth principles tailored to the Workers runtime.

## Before You Start

1. Read `references/security-checklist.md` -- it contains the full mapping of OWASP/CWE items to concrete Workers-specific mitigations. Consult it while generating code so nothing is missed.
2. Understand the user's requirements: what the Worker does, which bindings it uses (KV, R2, D1, Durable Objects, Queues, etc.), and what external services it talks to.
3. Ask clarifying questions if the scope is ambiguous, but default to the most secure option when in doubt.
4. Never display real or generated secrets, tokens, passwords, API keys, or cryptographic key material in code output, chat responses, or comments. Use placeholder values like `"YOUR_SECRET_HERE"` or references to environment variables (e.g. `env.API_SECRET`) instead. If you identify a secret the user has accidentally shared, warn them and do not repeat it.

## Architecture Principles

Every generated Worker follows these foundational principles. They are not arbitrary rules -- each one exists because violating it opens a door to one or more OWASP/CWE weaknesses.

### 1. Zero Trust Input Handling

All data arriving from outside the Worker (request bodies, query parameters, headers, path segments, WebSocket messages) is untrusted. Validate and sanitise everything before use. This directly addresses:

- **OWASP A05:2025 Injection** (SQL injection, header injection)
- **CWE-79** (XSS), **CWE-89** (SQLi), **CWE-94** (Code Injection)

**Implementation pattern:**

```typescript
// Use a validation library (e.g. zod) or hand-roll strict schemas
import { z } from "zod";

const CreateUserSchema = z.object({
  email: z.string().email().max(254),
  name: z.string().min(1).max(100).regex(/^[\p{L}\p{N}\s\-'.]+$/u),
  age: z.number().int().min(13).max(150),
});

// In your handler:
const parseResult = CreateUserSchema.safeParse(body);
if (!parseResult.success) {
  return errorResponse(400, "Invalid input", parseResult.error.flatten());
}
const validated = parseResult.data; // Use only this from here on
```

When constructing D1 queries, always use parameterised statements:

```typescript
// CORRECT -- parameterised
const result = await env.DB.prepare(
  "SELECT * FROM users WHERE email = ?1"
).bind(validated.email).first();

// NEVER do this:
// await env.DB.prepare(`SELECT * FROM users WHERE email = '${email}'`).first();
```

### 2. Strict Access Control

Every route and resource access check must be explicit. Never rely on obscurity or client-side checks. This addresses:

- **OWASP A01:2025 Broken Access Control** (including SSRF, IDOR, privilege escalation, CORS misconfiguration)
- **CWE-862** (Missing Authorisation), **CWE-863** (Incorrect Authorisation), **CWE-284** (Improper Access Control)

**Implementation pattern:**

```typescript
// Authenticate first, authorise second
async function requireAuth(
  request: Request,
  env: Env
): Promise<AuthenticatedUser> {
  const token = request.headers.get("Authorization")?.replace("Bearer ", "");
  if (!token) {
    throw new HttpError(401, "Authentication required");
  }

  // Validate token (JWT verification, session lookup, etc.)
  const user = await verifyToken(token, env);
  if (!user) {
    throw new HttpError(401, "Invalid or expired token");
  }
  return user;
}

// Resource-level authorisation -- never trust user-supplied IDs blindly
async function requireOwnership(
  user: AuthenticatedUser,
  resourceOwnerId: string
): Promise<void> {
  if (user.id !== resourceOwnerId && user.role !== "admin") {
    throw new HttpError(403, "Access denied");
  }
}
```

**CORS** must be explicit and restrictive:

```typescript
function corsHeaders(request: Request, env: Env): HeadersInit {
  const origin = request.headers.get("Origin") ?? "";
  const allowed = env.ALLOWED_ORIGINS?.split(",") ?? [];

  if (!allowed.includes(origin)) {
    return {}; // No CORS headers -- browser blocks it
  }

  return {
    "Access-Control-Allow-Origin": origin, // Never use "*" with credentials
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}
```

### 3. Robust Authentication and Session Management

This addresses **OWASP A07:2025 Identification and Authentication Failures** and **CWE-287** (Improper Authentication), **CWE-306** (Missing Authentication for Critical Function).

- Always verify JWTs cryptographically using `crypto.subtle.verify()` or `crypto.subtle.importKey()`. Never decode without verifying the signature.
- Use timing-safe comparison for secrets and tokens.
- Enforce rate limiting on authentication endpoints via Durable Objects or external rate limiters.

```typescript
// Timing-safe token comparison
async function timingSafeCompare(a: string, b: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode("comparison-key");
  const key = await crypto.subtle.importKey(
    "raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sigA = await crypto.subtle.sign("HMAC", key, encoder.encode(a));
  const sigB = await crypto.subtle.sign("HMAC", key, encoder.encode(b));
  return crypto.subtle.timingSafeEqual(sigA, sigB);
}
```

### 4. Cryptographic Correctness

This addresses **OWASP A04:2025 Cryptographic Failures** and **CWE-327** (Use of Broken Crypto), **CWE-328** (Use of Weak Hash), **CWE-916** (Insufficient Password Hashing).

- Use the Web Crypto API (`crypto.subtle`) for all cryptographic operations.
- Use `crypto.randomUUID()` for identifiers and `crypto.getRandomValues()` for random bytes.
- Never use `Math.random()` for anything security-sensitive.
- Use strong algorithms: AES-GCM for symmetric encryption, ECDSA/Ed25519 for signing, SHA-256+ for hashing.
- Store secrets via `wrangler secret put`, access them via `env`.

### 5. Secure Configuration and Supply Chain

This addresses **OWASP A02:2025 Security Misconfiguration** and **OWASP A03:2025 Software Supply Chain Failures**.

- Never commit secrets to source control. Use `wrangler secret put` and `.dev.vars` (gitignored).
- Keep `compatibility_date` current for latest runtime security patches.
- Enable `nodejs_compat` for access to `node:crypto` and other secure built-ins.
- Pin dependency versions. Audit with `npm audit` before deployment.
- Remove default/sample code, debug endpoints, and test routes before production.

### 6. Safe Error Handling and Logging

This addresses **OWASP A09:2025 Security Logging and Alerting Failures**, **OWASP A10:2025 Mishandling of Exceptional Conditions**, and **CWE-209** (Information Exposure Through Error Message), **CWE-532** (Log Injection).

```typescript
// Structured error response -- never leak internals
function errorResponse(
  status: number,
  message: string,
  details?: unknown
): Response {
  // In production, strip details
  const body: Record<string, unknown> = {
    error: message,
    status,
  };

  // Only include details in non-production
  if (details && !isProduction()) {
    body.details = details;
  }

  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// Structured logging -- sanitise user input before logging
function secureLog(
  level: "info" | "warn" | "error",
  message: string,
  context: Record<string, unknown>
): void {
  // Strip or encode control characters to prevent log injection
  const sanitised = Object.fromEntries(
    Object.entries(context).map(([k, v]) => [
      k,
      typeof v === "string"
        ? v.replace(/[\x00-\x1f\x7f]/g, "")
        : v,
    ])
  );
  console.log(JSON.stringify({ level, message, ...sanitised, ts: Date.now() }));
}
```

### 7. Secure-by-Default Response Headers

Every response should include security headers:

```typescript
function securityHeaders(): HeadersInit {
  return {
    "Content-Type": "application/json",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  };
}
```

### 8. No Global Mutable State

Workers reuse V8 isolates across requests. Storing request-scoped data in module-level variables causes cross-request data leaks -- a direct path to information disclosure (**CWE-200**, **CWE-212**).

```typescript
// WRONG -- leaks data between requests
let currentUser: User | null = null;

// CORRECT -- request-scoped
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const user = await authenticate(request, env); // scoped to this invocation
    return handleRequest(request, env, ctx, user);
  },
};
```

### 9. Resource Management and Resilience

This addresses **CWE-400** (Uncontrolled Resource Consumption) and contributes to **OWASP A10:2025**.

- Stream large request/response bodies instead of buffering (128MB memory limit).
- Set timeouts on external fetch calls.
- Enforce request body size limits.
- Use Queues or Workflows for background processing rather than blocking the request.

```typescript
// Enforce body size limit
async function readBodyWithLimit(
  request: Request,
  maxBytes: number
): Promise<ArrayBuffer> {
  const contentLength = parseInt(request.headers.get("Content-Length") ?? "0");
  if (contentLength > maxBytes) {
    throw new HttpError(413, "Request body too large");
  }

  const reader = request.body?.getReader();
  if (!reader) throw new HttpError(400, "Missing request body");

  const chunks: Uint8Array[] = [];
  let totalSize = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    totalSize += value.byteLength;
    if (totalSize > maxBytes) {
      reader.cancel();
      throw new HttpError(413, "Request body too large");
    }
    chunks.push(value);
  }

  const result = new Uint8Array(totalSize);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result.buffer;
}
```

## Output Structure

When generating a Worker, produce the following files:

1. **`src/index.ts`** -- the main Worker entry point using ES modules format.
2. **`src/types.ts`** -- shared types and interfaces (Env, request/response shapes).
3. **`src/middleware.ts`** -- reusable middleware (auth, validation, CORS, rate limiting, error handling).
4. **`src/routes.ts`** or route-specific files -- business logic, cleanly separated.
5. **`wrangler.jsonc`** -- configuration with current `compatibility_date`, `nodejs_compat`, observability enabled, and bindings declared.
6. **`tsconfig.json`** -- strict TypeScript configuration.
7. **`.dev.vars.example`** -- template for local secrets (never real values).

For simpler Workers (single-purpose, few routes), consolidate into a single `src/index.ts` but maintain the same security patterns.

## Code Generation Checklist

Before finalising generated code, verify every item on this list. Each maps to one or more OWASP/CWE items (see `references/security-checklist.md` for the full mapping):

- [ ] All user input validated with strict schemas before use
- [ ] All database queries use parameterised statements
- [ ] Authentication is required on every non-public endpoint
- [ ] Authorisation checks are performed at the resource level (not just route level)
- [ ] CORS configuration is explicit and restrictive
- [ ] Secrets accessed via `env`, never hardcoded
- [ ] Cryptographic operations use Web Crypto API with strong algorithms
- [ ] `Math.random()` is never used for security purposes
- [ ] Error responses never leak stack traces, internal paths, or system details
- [ ] Security response headers are set on every response
- [ ] No global mutable state
- [ ] Request body size limits enforced
- [ ] External fetches have timeouts and error handling
- [ ] Logging sanitises user-controlled data (no log injection)
- [ ] `compatibility_date` is set to a recent date
- [ ] Dependencies are minimal and pinned
- [ ] Content-Type is validated on incoming requests where relevant
- [ ] Path traversal is prevented (no user input in file paths without sanitisation)
- [ ] SSRF is prevented (outbound URLs are validated against an allowlist)
- [ ] Race conditions are considered for shared state (use Durable Objects for coordination)
- [ ] Output encoding applied when generating HTML responses

## Example: Secure API Worker Skeleton

```typescript
// src/index.ts
import { z } from "zod";

interface Env {
  DB: D1Database;
  API_SECRET: string;
  ALLOWED_ORIGINS: string;
}

class HttpError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
  }
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    try {
      // CORS preflight
      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: {
            ...corsHeaders(request, env),
            ...securityHeaders(),
          },
        });
      }

      const url = new URL(request.url);
      const response = await routeRequest(url, request, env, ctx);

      // Apply security headers to every response
      const headers = new Headers(response.headers);
      for (const [k, v] of Object.entries(securityHeaders())) {
        headers.set(k, v);
      }
      for (const [k, v] of Object.entries(corsHeaders(request, env))) {
        headers.set(k, v);
      }

      return new Response(response.body, {
        status: response.status,
        headers,
      });
    } catch (err) {
      if (err instanceof HttpError) {
        return errorResponse(err.status, err.message);
      }
      secureLog("error", "Unhandled exception", {
        path: new URL(request.url).pathname,
        method: request.method,
      });
      return errorResponse(500, "Internal server error");
    }
  },
};

// ... (implement corsHeaders, securityHeaders, errorResponse,
//      secureLog, routeRequest as shown in the patterns above)
```

## Secure Design Considerations

When the user's requirements involve any of these patterns, apply the corresponding security measures:

| User Requirement | Security Consideration | OWASP/CWE Reference |
|---|---|---|
| File upload (R2) | Validate content type, enforce size limits, scan filenames for path traversal | A01, CWE-22 |
| User authentication | Use proven JWT libraries, timing-safe comparison, rate limit login attempts | A07, CWE-287 |
| Database queries (D1) | Parameterised queries only, limit result sets, validate column names if dynamic | A05, CWE-89 |
| Webhook receiver | Verify signatures (HMAC), validate payload schema, idempotency keys | A04, A07, CWE-345 |
| HTML generation | Context-aware output encoding, Content-Security-Policy headers | A05, CWE-79 |
| External API calls | Allowlist target URLs (prevent SSRF), timeout, validate responses | A01, CWE-918 |
| Caching (KV) | Never cache sensitive data without encryption, set appropriate TTLs | A04, CWE-524 |
| WebSockets (DO) | Authenticate on connection, validate every message, rate limit per connection | A01, A07, CWE-20 |
| Scheduled tasks (Cron) | Validate cron handler is not externally triggerable, log execution | A01, A09 |

## What Not To Do

These anti-patterns appear frequently and each one opens a real vulnerability:

- Using string concatenation or template literals to build SQL or HTML
- Trusting `Content-Type` headers without verifying the actual body format
- Using `*` for `Access-Control-Allow-Origin` when credentials are involved
- Catching errors silently with empty catch blocks
- Storing JWTs or session tokens in URLs or query parameters
- Logging full request bodies (may contain credentials or PII)
- Using `eval()`, `new Function()`, or `setTimeout` with string arguments
- Assuming Cloudflare's edge network handles all security (it handles transport, not application logic)
- Using `passThroughOnException()` without understanding it sends raw requests to origin on failure
