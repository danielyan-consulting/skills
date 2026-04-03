# Validation Patterns Reference

This document catalogues validation strategies and the threat model to apply when
auditing a codebase for input-validation gaps. It is organised by validation
category, with language-agnostic guidance and cross-language examples.

---

## Table of contents

1. [Threat model -- where untrusted data enters](#1-threat-model)
2. [Whitelisting (allowlisting)](#2-whitelisting)
3. [Type enforcement](#3-type-enforcement)
4. [Format validation with regular expressions](#4-format-validation)
5. [Length and size constraints](#5-length-and-size-constraints)
6. [Numeric range checks](#6-numeric-range-checks)
7. [Encoding and escaping for output context](#7-encoding-and-escaping)
8. [Parameterised queries](#8-parameterised-queries)
9. [Path traversal prevention](#9-path-traversal-prevention)
10. [Deserialisation safety](#10-deserialisation-safety)
11. [File upload validation](#11-file-upload-validation)
12. [Redirect and URL validation](#12-redirect-and-url-validation)
13. [Schema validation](#13-schema-validation)
14. [Rate limiting and abuse prevention](#14-rate-limiting)
15. [Secrets detection patterns](#15-secrets-detection)
16. [Why blacklisting fails](#16-why-blacklisting-fails)
17. [Common language-specific pitfalls](#17-language-specific-pitfalls)

---

## 1. Threat model

Untrusted data can enter a system through many channels. When auditing, check
all of the following:

**Direct user input:** query parameters, path parameters, request headers
(including cookies), request body (JSON, XML, form-encoded, multipart),
WebSocket messages, gRPC request fields, GraphQL variables and arguments.

**Indirect user input:** file uploads (name, content, MIME type, metadata),
uploaded archives (zip, tar -- beware zip-slip), imported CSV/Excel/XML data,
URLs provided by users (SSRF risk), callback/webhook URLs, OAuth redirect URIs.

**Inter-service input:** messages from queues (SQS, RabbitMQ, Kafka, NATS),
events from event buses, responses from third-party APIs, data read from shared
databases or caches, environment variables set by orchestrators.

**Infrastructure input:** DNS responses, HTTP headers from reverse proxies or
load balancers (X-Forwarded-For, Host), TLS client certificates, SAML/OIDC
assertions.

**Stored data re-read:** data that was written to a database or file system and
later read back. If it was not validated at write time, it is still untrusted at
read time (stored XSS, second-order injection).

---

## 2. Whitelisting

The principle: define the set of acceptable values and reject everything else.

**Enum/set membership:**
```
# Pseudocode
ALLOWED_ROLES = {"admin", "editor", "viewer"}
if role not in ALLOWED_ROLES:
    reject("Invalid role")
```

**Character class allowlists:**
```
# Allow only alphanumeric and hyphens for a slug
if not re.match(r'^[a-zA-Z0-9\-]+$', slug):
    reject("Invalid slug format")
```

**Domain allowlists (for URLs, redirects, email domains):**
```
ALLOWED_DOMAINS = {"example.com", "cdn.example.com"}
parsed = parse_url(input_url)
if parsed.host not in ALLOWED_DOMAINS:
    reject("Redirect target not allowed")
```

Whitelisting is preferred over blacklisting in every case. See section 16 for
why blacklisting fails.

---

## 3. Type enforcement

Ensure the incoming value is coerced to the expected type as early as possible.
Reject the request if coercion fails -- never silently fall back.

| Language family | Integer coercion example                       |
|-----------------|-------------------------------------------------|
| Python          | `int(value)` in a try/except                   |
| JavaScript/TS   | `Number.parseInt(value, 10)` then `isNaN` check |
| Java            | `Integer.parseInt(value)` in try/catch          |
| Go              | `strconv.Atoi(value)` checking the error        |
| C#              | `int.TryParse(value, out var result)`           |
| Ruby            | `Integer(value)` (raises on non-integer)        |
| PHP             | `filter_var($v, FILTER_VALIDATE_INT)`           |

Also watch for implicit type coercion that can be exploited -- e.g. JavaScript's
loose equality, PHP's type juggling, or Python's `bool("")` being False.

---

## 4. Format validation

Use regular expressions or dedicated parsers to validate structured strings.

| Data type     | Strategy                                                       |
|---------------|----------------------------------------------------------------|
| Email         | Regex for basic shape + length cap; for strictness use a library |
| URL           | Parse with a URL library; check scheme is http/https; check host against allowlist |
| UUID          | `^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$` |
| ISO 8601 date | `^\d{4}-\d{2}-\d{2}$` then parse to confirm validity          |
| Phone number  | Use a library like libphonenumber; regex alone is fragile       |
| IP address    | Parse with inet_pton or equivalent; check version              |
| Credit card   | Luhn check + length + known prefix ranges                      |
| Postcode      | Country-specific regex or library                              |

Avoid overly permissive regexes such as `.*` or `.+` in places where stricter
patterns are possible.

---

## 5. Length and size constraints

Every text, binary, and collection input should have explicit upper bounds.

- **Strings:** enforce a maximum character length (and minimum where appropriate).
- **Request bodies:** enforce a maximum payload size at the web-server/framework
  level (e.g. Express `limit: '100kb'`, Nginx `client_max_body_size`).
- **Arrays and collections:** enforce a maximum element count to prevent
  denial-of-service or algorithmic-complexity attacks.
- **File uploads:** enforce a maximum file size both at the framework level and
  in application logic.
- **Nested structures:** enforce a maximum nesting depth (especially for JSON and
  XML) to prevent billion-laughs or stack-overflow attacks.

---

## 6. Numeric range checks

Any numeric input should be checked for:

- **Lower bound** (e.g. quantity >= 1, age >= 0)
- **Upper bound** (e.g. quantity <= 10000, page_size <= 100)
- **Integer vs. float** -- if only integers are expected, reject floats
- **NaN and Infinity** -- in JavaScript and similar, explicitly reject these
- **Negative zero** -- rarely exploitable but worth normalising

---

## 7. Encoding and escaping

Output encoding depends on context:

| Context      | Encoding / escaping strategy                           |
|--------------|--------------------------------------------------------|
| HTML body    | HTML-entity encode (`<` becomes `&lt;`)                |
| HTML attribute | Attribute-encode; always quote attribute values       |
| JavaScript   | JavaScript-escape; prefer JSON.stringify for data injection |
| CSS          | CSS-escape; avoid injecting user data into stylesheets |
| URL parameter| Percent-encode (encodeURIComponent / equivalent)       |
| SQL          | Use parameterised queries (see section 8)              |
| Shell/OS cmd | Avoid shell invocation; if unavoidable, use array-form exec |
| XML          | XML-entity encode; disable DTDs and external entities  |
| LDAP         | LDAP-escape special characters                         |
| Log output   | Strip or encode newlines and control characters (log injection) |

---

## 8. Parameterised queries

String concatenation to build SQL (or NoSQL) queries is always a critical
finding. The fix is parameterised/prepared statements:

```
# BAD (SQL injection)
query = "SELECT * FROM users WHERE id = " + user_id

# GOOD (parameterised)
query = "SELECT * FROM users WHERE id = ?"
execute(query, [user_id])
```

This applies equally to:
- SQL (MySQL, PostgreSQL, SQLite, MSSQL, Oracle)
- NoSQL (MongoDB: use driver's query builders, never build query objects from
  raw JSON strings)
- ORM raw-query escape hatches (e.g. Django's `raw()`, ActiveRecord's
  `find_by_sql`, Sequelize's `sequelize.query`)
- LDAP queries
- GraphQL resolvers building downstream queries

---

## 9. Path traversal prevention

When user input influences a file path:

1. **Canonicalise** the path (resolve symlinks, `.`, `..`).
2. **Confine** the result to the expected base directory by checking that the
   canonical path starts with the base directory's canonical path.
3. **Reject** null bytes (`\0`) in the path.
4. **Use allowlists** for file extensions if applicable.

```
# Pseudocode
canonical = realpath(join(BASE_DIR, user_input))
if not canonical.startswith(realpath(BASE_DIR)):
    reject("Path traversal detected")
```

---

## 10. Deserialisation safety

Deserialising untrusted data with a general-purpose deserialiser can lead to
remote code execution.

| Language | Dangerous                    | Safer alternative                        |
|----------|------------------------------|------------------------------------------|
| Python   | `pickle.loads()`             | `json.loads()`, `msgpack`, protobuf      |
| Java     | `ObjectInputStream`          | JSON (Jackson/Gson), protobuf            |
| PHP      | `unserialize()`              | `json_decode()`                          |
| Ruby     | `Marshal.load()`, `YAML.load()` | `JSON.parse()`, `YAML.safe_load()`   |
| .NET     | `BinaryFormatter`            | `System.Text.Json`, protobuf             |
| Node.js  | `node-serialize`             | `JSON.parse()` with schema validation    |

---

## 11. File upload validation

- **Validate MIME type** from the file's magic bytes, not from the
  Content-Type header (which the client controls).
- **Enforce an allowlist of permitted file extensions.**
- **Rename uploaded files** to a random or UUID-based name; never use the
  original filename directly (it may contain path-traversal sequences or
  OS-specific special names like `CON`, `NUL`, `..`).
- **Store uploads outside the web root** or in a dedicated object store.
- **Scan for malware** if feasible.
- **Enforce size limits.**

---

## 12. Redirect and URL validation

Open-redirect vulnerabilities arise when an application redirects to a
user-supplied URL without validation.

- Parse the URL with a proper URL parser.
- Check the scheme is `http` or `https` (reject `javascript:`, `data:`, etc.).
- Check the host against an allowlist of permitted redirect targets.
- Never rely on string-prefix checks alone (e.g. `url.startswith("https://example.com")`
  is defeated by `https://example.com.evil.com`).

For SSRF prevention, additionally:
- Resolve the hostname and reject private/internal IP ranges (127.0.0.0/8,
  10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, fd00::/8).
- Be aware of DNS rebinding (resolve, check, then use the same resolved IP).

---

## 13. Schema validation

For structured request bodies (JSON, XML, YAML), validate against a schema
before processing:

- **JSON:** JSON Schema, Zod (TypeScript), Pydantic (Python), Marshmallow
  (Python), Joi (Node.js), Cerberus (Python), ajv (Node.js), Jackson with
  annotations (Java), FluentValidation (.NET).
- **XML:** XSD or RelaxNG schema validation; always disable DTD processing and
  external entity resolution (XXE prevention).
- **GraphQL:** leverage the built-in type system; add custom scalar validation;
  enforce query complexity/depth limits.
- **Protobuf/gRPC:** the schema provides type safety but does NOT enforce
  business-logic constraints such as ranges, formats, or allowed values --
  add those in application logic.

---

## 14. Rate limiting

While not strictly input validation, rate limiting prevents abuse of validated
endpoints:

- Per-IP or per-user request rate limits.
- Per-endpoint limits for expensive operations (login, search, export).
- Payload-size limits at the reverse-proxy level.
- Pagination limits (max page size, max offset).

Flag the absence of rate limiting as a Medium finding when the endpoint is
publicly accessible and handles authentication or data retrieval.

---

## 15. Secrets detection

Patterns to scan for when looking for hardcoded secrets:

- Variable names containing: password, passwd, pwd, secret, token, api_key,
  apikey, api-key, auth, credential, private_key, access_key, connection_string,
  signing_key, encryption_key, client_secret, bearer.
- Assignment of string literals to these variables.
- High-entropy strings (>4.5 Shannon entropy for 20+ char strings) assigned to
  any variable.
- PEM blocks: `-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`
- AWS-style keys: `AKIA[0-9A-Z]{16}`
- Generic hex/base64 tokens >= 32 characters in config files.
- Connection strings with `password=`, `pwd=`, `passwd=` embedded.
- `.env` files committed to the repository.

When reporting, ALWAYS replace the actual value with `REDACTED`. Never display
the secret, not even partially.

---

## 16. Why blacklisting fails

Blacklisting (also called denylisting or negative-security) attempts to block
known-bad inputs. This approach is inherently flawed:

- **Incompleteness:** attackers constantly discover new payloads; no denylist
  is ever exhaustive.
- **Encoding bypasses:** the same attack can be encoded in many ways (URL
  encoding, double encoding, Unicode normalisation, case variation, null-byte
  injection) to evade string-matching denylists.
- **Context sensitivity:** a character that is dangerous in one context (e.g.
  `<` in HTML) is harmless in another (e.g. a numeric comparison). Blacklists
  tend to either over-block (breaking legitimate input) or under-block (missing
  context-specific attacks).
- **Maintenance burden:** every new vulnerability requires updating the
  denylist; whitelists require no update unless the set of legitimate values
  changes.

If you find existing validation that uses a blacklist approach, flag it and
rewrite the recommendation as a whitelist.

---

## 17. Common language-specific pitfalls

### JavaScript / TypeScript
- Prototype pollution via `Object.assign` or spread with user-controlled keys.
- `eval()`, `Function()`, `setTimeout(string)` with user input.
- `require()` or dynamic `import()` with user-controlled paths.
- Regex denial of service (ReDoS) from catastrophic backtracking.
- `__proto__`, `constructor`, `prototype` keys in user JSON.

### Python
- `eval()`, `exec()`, `compile()` with user input.
- `pickle.loads()` on untrusted data.
- `os.system()`, `subprocess.Popen(shell=True)` with user strings.
- Format-string attacks via `str.format()` or f-strings with user-controlled
  template strings.
- YAML `yaml.load()` without `Loader=SafeLoader`.

### Java
- `Runtime.exec()` with unsanitised arguments.
- XML External Entity (XXE) via default `DocumentBuilderFactory` settings.
- `ObjectInputStream.readObject()` on untrusted streams.
- Server-Side Request Forgery via `URL.openConnection()` on user URLs.
- Expression Language (EL) injection in JSP/JSF.

### PHP
- `eval()`, `preg_replace` with `/e` modifier.
- `unserialize()` on user input.
- Type juggling in loose comparisons (`==` vs `===`).
- `include` / `require` with user-controlled paths (LFI/RFI).
- `extract()` on user arrays (variable injection).

### Go
- `os/exec.Command` with shell expansion via `bash -c`.
- `html/template` vs `text/template` confusion (the latter does no escaping).
- SQL string concatenation (use `database/sql` placeholders).
- Unbounded `io.ReadAll` on HTTP request bodies.

### C / C++
- Buffer overflows from `strcpy`, `sprintf`, `gets` without bounds checking.
- Integer overflow/underflow leading to undersized allocations.
- Format-string vulnerabilities from `printf(user_input)`.
- Use-after-free in complex input-parsing state machines.

### Ruby
- `eval()`, `send()` with user-controlled method names.
- `YAML.load()` (use `YAML.safe_load()`).
- `ERB.new(user_input).result` (template injection).
- Mass assignment without strong parameters.

### C# / .NET
- `BinaryFormatter` deserialisation.
- SQL concatenation (use `SqlCommand.Parameters`).
- LDAP injection via string-built LDAP filters.
- `Process.Start` with unsanitised arguments.
- Over-posting / mass assignment without `[Bind]` or DTOs.

### Shell / Bash
- Unquoted variable expansion: `rm $file` vs `rm "$file"`.
- Command substitution with user input.
- Glob injection.
- Sourcing or evaling user-provided strings.

### Infrastructure as Code (Terraform, CloudFormation, etc.)
- Hardcoded secrets in resource definitions.
- Overly permissive IAM policies or security-group rules derived from
  variable inputs without validation.
- Unvalidated variable inputs used in resource names, CIDR blocks, or ARNs.
