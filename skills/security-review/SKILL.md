---
name: security-review
description: Framework-agnostic security audit skill. Detects the project's tech stack, then runs universal and stack-specific security checks aligned with OWASP Top 10:2025, OWASP API Security Top 10:2023, OWASP LLM Top 10:2025, OWASP Mobile Top 10:2024, and CWE Top 25:2025. Use when reviewing code for vulnerabilities, running a security audit, pen testing, checking authentication/authorization/injection/file-upload/OAuth flows, or before a production deploy or client handoff.
---

# /security-review

A structured, framework-agnostic security audit skill. Detects the project's tech stack first, then runs a fixed set of universal security checks plus stack-specific checks relevant to what was detected. Output format mirrors `/review` — severity-tagged findings, no automatic fixes unless explicitly requested.

Aligned with five current, independently-sourced standards — not an invented checklist:
- **OWASP Top 10:2025** (owasp.org/Top10/2025) — general web application risks
- **OWASP API Security Top 10:2023** (owasp.org/API-Security) — API-specific risks
- **OWASP Top 10 for LLM Applications 2025** (genai.owasp.org) — AI/LLM/agentic risks
- **OWASP Mobile Top 10:2024** (owasp.org/www-project-mobile-top-10) — mobile app-specific risks, first major update since 2016
- **CWE Top 25:2025** (cwe.mitre.org/top25) — MITRE's real-world CVE-data-driven weakness ranking

## When to use

- After any feature involving auth, payments, file uploads, OAuth, or user input
- Before any production deploy or client handoff
- On explicit trigger: `/security-review`, "run a security review", "security-review this", "audit this for vulnerabilities", "pen test this"
- Should run at least once before go-live, and again after any major auth/integration feature
- Works on any project — Laravel, Node/Express, Django, Rails, plain PHP, React/Next.js frontends, Rust/Go/C++ backends, AI/LLM-powered features, etc.
- Diff-aware: when reviewing a specific PR/branch/recent change set, scope the review to changed files first, then note if any change touches a security-sensitive area (auth, secrets, file I/O, external calls, LLM prompts) that warrants a wider check of the surrounding code.

## Step 0 — Detect the stack

Before checking anything, identify what's actually in the project. Look for, in order:

- `composer.json` → PHP project. Check `require` for `laravel/framework`, `symfony/*`, or plain PHP.
- `package.json` → Node project. Check `dependencies`/`devDependencies` for `next`, `express`, `react`, `vue`, `@angular/core`, etc.
- `requirements.txt` / `pyproject.toml` → Python. Check for `django`, `flask`, `fastapi`.
- `Gemfile` → Ruby. Check for `rails`.
- `go.mod` → Go.
- `Cargo.toml` → Rust. Note ownership/unsafe-block boundaries if present.
- Memory-unsafe languages present (C, C++, and unsafe Rust blocks) → also run the Memory Safety checks under Category 5 (Injection/CWE crossover) below — these languages carry real weight in the current CWE Top 25 (Use After Free, Out-of-bounds Read/Write, Buffer Overflows all rank in the top 16).
- Any LLM/AI SDK present (`openai`, `anthropic`, `@anthropic-ai/sdk`, `langchain`, `llamaindex`, or a custom agent/tool-calling framework) → also run the AI/LLM stack-specific checks in Step 2.
- Any API-first project (REST/GraphQL endpoints as the primary interface, OpenAPI/Swagger spec present) → also run the API-specific checks in Step 2 with extra weight, since these are validated against a dedicated OWASP list.
- Mobile stack present (`android/` + `ios/` dirs, `pubspec.yaml` for Flutter, `.xcodeproj`/`Podfile` for native iOS, `build.gradle` for native Android, React Native's `metro.config.js`, Xamarin/MAUI `.csproj`, or Cordova/Ionic `config.xml`) → also run the Mobile-specific checks in Step 2.
- Infrastructure-as-code present (`Dockerfile`, `*.tf`, `k8s/*.yaml`, `docker-compose.yml`) → also run the Infrastructure & Deployment category below.
- Multiple of the above → treat as a multi-stack project (e.g. Laravel backend + separate JS frontend + LLM feature) and run checks against each part separately, scoped to the relevant directory.

State the detected stack explicitly at the start of the review output. If detection is ambiguous, ask rather than guessing.

## Step 1 — Universal checks (run on every project, regardless of stack)

Categories 1–10 map directly to OWASP Top 10:2025 (A01–A10). Categories 11–13 are additional checks not covered by that list but still relevant to a full review, sourced from CWE Top 25 real-world data and standard manual-pentest practice.

### 1. Broken Access Control (OWASP A01:2025 · CWE-862, CWE-863, CWE-284, CWE-639, CWE-306)
- Every protected route/endpoint actually behind auth middleware/guard — grep all route definitions for unguarded state-changing endpoints
- Role/permission checks present at more than one layer where the framework supports it (middleware + policy/guard, or equivalent) — defense in depth
- **BOLA (Broken Object Level Authorization)**: does every endpoint that accepts an object ID (order, invoice, user, file) verify the requesting user actually owns/can access that specific object, not just that they're authenticated? This is the #1 real-world API vulnerability (~40% of API attacks per industry data) — check it explicitly on every resource-scoped endpoint.
- **CWE-639 — Authorization Bypass Through User-Controlled Key**: a named, currently-rising (+6 ranks in 2025) variant of the above — specifically check any endpoint where an ID/key in the request body or query string (not just the URL path) determines which record is acted on.
- **BFLA (Broken Function Level Authorization)**: can a lower-privileged user invoke an admin-level function by calling its endpoint directly (bypassing UI-level hiding)? Check every admin/privileged action has a server-side role check, not just a hidden button.
- **Missing Authorization (CWE-862, #4 on CWE Top 25)** vs **Incorrect Authorization (CWE-863)**: distinguish "no check exists at all" from "a check exists but the logic is wrong" — both are real findings, but the fix differs.
- **SSRF (Server-Side Request Forgery)**: any endpoint that fetches a URL supplied by user input (webhooks, image-by-URL, PDF generation, link previews) — confirm it validates/blocks requests to internal IP ranges, cloud metadata endpoints (`169.254.169.254`), and non-HTTP(S) schemes.
- **CWE-306 — Missing Authentication for Critical Function**: confirm every state-changing or sensitive-data-returning endpoint actually requires authentication — don't assume based on route grouping alone, verify the middleware chain is actually applied.
- Session fixation: session regenerated on login, invalidated on logout
- Mass assignment / over-posting: confirm sensitive fields (role, status, is_admin, price, owner_id, balance) cannot be set by user input on create/update endpoints
- CORS policy restricts origins to trusted domains, directory listing disabled

### 2. Security Misconfiguration (OWASP A02:2025)
- Debug/development mode confirmed OFF in production config
- Security headers present where applicable (CSP, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy) — flag absence as Minor/Important depending on the app's exposure
- Default/example credentials (seeders, `.env.example`, fixture data) never match real production values
- Insecure defaults not left unchanged (default admin passwords, open storage buckets, permissive database bind addresses, unused services/ports left enabled)
- Error messages return generic responses in production, never stack traces
- This category surged from #5 to #2 in OWASP's 2025 dataset — misconfigurations in cloud/container/proxy/WAF/bucket setups are now the second most common real-world finding. Take it as seriously as access control.

### 3. Software Supply Chain Failures (OWASP A03:2025)
- Dependency audit tool run for the detected stack and results reviewed (`composer audit` for PHP, `npm audit`/`pnpm audit`/`yarn audit` for Node, `pip-audit` for Python, `bundle audit` for Ruby, `cargo audit` for Rust) — flag any Critical/High severity finding even if a decision is made to defer it
- Lockfiles present and committed (`composer.lock`, `package-lock.json`/`pnpm-lock.yaml`, etc.) to prevent supply-chain drift
- Dependencies pinned to specific versions where the ecosystem allows it, not loose ranges on anything security-sensitive
- Typosquatting risk: recently-added dependencies with low download counts or names suspiciously close to popular packages, if inspectable
- CI/CD pipeline itself reviewed: are build/deploy steps pulling unpinned third-party GitHub Actions or scripts, is there any unreviewed auto-update mechanism
- This is the highest-incidence category in OWASP's 2025 dataset (5.19% average incidence) — do not treat it as a lower-priority checkbox

### 4. Cryptographic Failures (OWASP A04:2025)
- No weak/broken algorithms (MD5, SHA1, DES, RC4, 3DES) used for anything security-relevant — hashing passwords, signing tokens, encrypting sensitive data
- Passwords hashed with a proper adaptive algorithm (bcrypt, Argon2, scrypt) — never plain, never reversibly encrypted
- Approved standards where custom crypto is used: AES-256, RSA ≥2048 bits, ECC P-256/P-384/P-521
- Random values used for tokens/secrets/nonces come from a cryptographically secure source, not `Math.random()` or `rand()`
- Key management: encryption keys not hardcoded, not committed, rotated where the framework supports it
- TLS enforced for data in transit; sensitive data encrypted at rest where applicable

### 5. Injection (OWASP A05:2025 · CWE-79, CWE-89, CWE-78, CWE-77, CWE-94)
- **XSS (CWE-79) — Cross-site Scripting**: the #1 ranked weakness in CWE's 2025 real-world CVE data. Give this explicit, standalone attention, not just a bullet inside generic injection. Check every place user-controlled data reaches HTML output — template auto-escaping relied upon by default, any `{!! !!}`/`dangerouslySetInnerHTML`/`innerHTML =`/`v-html`/`| safe` usage individually justified.
- **SQL Injection (CWE-89)** — #2 ranked. Raw SQL / string-concatenated queries must be parameterized or absent (grep for `execute.*\+`, `query.*\+`, `SELECT.*%` as a starting signal, then read the actual construction). ORM methods accepting raw fragments (`whereRaw`, `.raw()`) with unsanitized input.
- **OS Command Injection (CWE-78)** and **Command Injection (CWE-77)**: any shell/process execution with user-controlled input (`exec`, `eval`, `system`, `shell_exec`, `subprocess.call`, `child_process.exec`).
- **Code Injection (CWE-94)**: dynamic code generation/execution from user input (`eval()`, `new Function()`, PHP `create_function`, unsafe template compilation).
- LDAP injection, XPath injection, NoSQL injection (`$where`, unsanitized Mongo query objects), XXE (XML External Entity parsing from untrusted sources)
- Path traversal (CWE-22, #6 on CWE Top 25): file path construction from user input via `../` in filenames or IDs
- If the project has any LLM/AI-agent feature accepting user input that reaches a prompt: check for prompt injection exposure — see the dedicated AI/LLM section in Step 2, this is a large enough surface to warrant its own checklist.

### 6. Insecure Design
- Was the security-sensitive feature (auth, payments, permissions, file access) threat-modeled at all, even informally — or was security bolted on after the fact? Note this as a process observation, not just a code finding.
- Missing rate limiting at the architecture level on sensitive flows (login, password reset, payment, expensive computation endpoints) — not just "is there a rate limiter library," but "is it actually applied to the flows that need it"
- Business-critical operations lack a defense-in-depth design (e.g. a single check gates an irreversible action, with no confirmation step, no audit trail, no secondary verification)
- Trust boundaries: does the design assume client-supplied data is trustworthy anywhere it shouldn't be

### 7. Authentication Failures (OWASP A07:2025)
- MFA available/enforced where the sensitivity of the application warrants it
- Weak password policy, no rate limiting or account lockout on repeated login failures
- Credentials never sent over non-HTTPS
- Session tokens: cryptographically secure random generation, sufficient entropy, regenerated post-login
- Cookies: `HttpOnly`, `Secure` (in production), `SameSite` set appropriately, with reasonable absolute and idle timeouts
- JWTs (if used): signature actually verified, algorithm explicitly allow-listed (`alg: none` must never be accepted), expiry enforced, refresh tokens handled securely (rotated, revocable)
- Breached-credential checking or account enumeration prevention considered for public-facing auth (informational for smaller apps, Important for anything handling real customer accounts)
- Password reset / invite / magic-link tokens: single-use, expiring, not guessable

### 8. Software or Data Integrity Failures (OWASP A08:2025 · CWE-502)
- **Deserialization of Untrusted Data (CWE-502, #15 on CWE Top 25 and rising)**: any endpoint that deserializes user-controlled data (PHP `unserialize()`, Python `pickle.loads()`, Java native serialization, Node `eval`-based parsing) without a safe-format alternative
- Auto-update or plugin/extension mechanisms verify signatures/checksums before applying, if the project has any such mechanism
- CI/CD artifacts and build outputs are signed or otherwise verified before deployment, where the platform supports it
- Third-party scripts loaded on frontend pages (analytics, chat widgets, ad tags) are from trusted, ideally subresource-integrity-checked sources — flag unpinned third-party `<script src>` tags on pages handling sensitive data (e.g. checkout, login)

### 9. Security Logging and Alerting Failures (OWASP A09:2025)
- Authentication attempts (user, timestamp, action, outcome) and authorization denials (user, resource, reason) are actually logged
- Logs never contain passwords, tokens, full payment details, or unnecessary PII (CWE-532) — sanitize log entries (CWE-117) to prevent log injection via unescaped user input written into log lines
- Logging exists, but also ask: does anything actually alert on it? A log nobody reads doesn't prevent an incident — flag if there's no alerting/monitoring layer on authentication anomalies, repeated failures, or privilege escalations, appropriate to the project's scale
- Timestamps synchronized/consistent with timezone info for forensic usability

### 10. Mishandling of Exceptional Conditions (OWASP A10:2025 — new for 2025)
- Fail-open patterns: does any error/exception path default to granting access, skipping a check, or treating an unhandled case as success? Grep for bare/broad `catch`/`except` blocks that swallow errors and continue as if nothing happened.
- Are multi-step transactions rolled back completely on interruption (fail closed), or can a partial failure leave data in an inconsistent, exploitable state?
- Verbose error messages / stack traces never shown to end users in production mode, and never leak internal paths, query structure, or dependency versions (CWE-200 — Exposure of Sensitive Information)
- Centralized error handling exists rather than scattered, inconsistent per-endpoint error logic
- **Resource exhaustion / DoS (CWE-770 — Allocation of Resources Without Limits or Throttling, rising on CWE Top 25)**: are there guards against unbounded loops, unbounded recursion, or unbounded input size on anything user-triggerable

### 11. File Handling (CWE-434 — Unrestricted Upload of File with Dangerous Type)
(Its concerns are split across A01/A05/A08 above, but kept as a dedicated checklist here since file upload is a common, concrete attack surface worth checking explicitly, and CWE-434 ranks in the current CWE Top 25.)
- Upload MIME type validated server-side, never trusting client-declared type or file extension alone
- Upload size limits enforced server-side
- Uploaded filenames sanitized before use in any path construction
- Uploaded files never stored with executable permissions or inside a publicly-web-servable, executable directory
- Large-scale third-party upload handling flagged for malware-scanning consideration (informational only, not blocking for small internal tools)

### 12. Business Logic Flaws
(Not an OWASP Top 10 category by name, but a well-documented real-world attack class every manual pentest checklist includes — automated scanners miss these.)
- Race conditions / TOCTOU (time-of-check-time-of-use) on anything involving balances, inventory, one-time-use codes, or limited quantities
- Workflow bypass: can a multi-step process (e.g. payment → fulfillment) be short-circuited by hitting a later-stage endpoint directly out of order
- Client-side-only validation of business rules (price, quantity, eligibility) with no server-side enforcement of the same rule

### 13. Infrastructure & Deployment (only if IaC/deployment config is present in the repo)
- `Dockerfile`: no `root` user for the running process where avoidable, no secrets baked into image layers, minimal base image
- CI/CD config: secrets referenced via the platform's secret store, never hardcoded in workflow YAML
- Cloud IaC (`*.tf`, CloudFormation, etc.): no publicly-open security groups/storage buckets, no wildcard IAM policies

## Step 2 — Stack-specific checks (add on top of universal checks, only for detected stack)

**If Laravel detected**, additionally check:
- `$fillable`/`$guarded` on every model reviewed specifically
- Route model binding used instead of manual `find()`/`findOrFail()` with unvalidated IDs where practical
- `APP_DEBUG=false` and `APP_ENV=production` confirmed for prod config
- Queue jobs handling external API calls: no secrets logged in job payloads/failed_jobs table
- Mass assignment vulnerabilities via `$request->all()` passed directly to `create()`/`update()` without validation

**If Node/Express detected**, additionally check:
- `helmet` or equivalent security-header middleware present
- No `eval()` or `new Function()` with user input
- JWT: signature verified, algorithm explicitly allow-listed (not `alg: none` accepted)
- Environment variables loaded securely, not committed `.env` files

**If a React/Next.js/Vue frontend detected**, additionally check:
- No secrets in `NEXT_PUBLIC_*` / `VITE_*` / any client-bundled env variable
- `dangerouslySetInnerHTML`/`v-html` usage reviewed for XSS
- Client-side auth checks (hiding a button/route) not relied upon as the actual security boundary — server must re-check

**If Django/Flask/FastAPI detected**, additionally check:
- `DEBUG = False` in production settings
- ORM usage avoids raw cursor execution with string-formatted input
- CSRF middleware enabled (Django) / explicit CSRF handling present (Flask/FastAPI)
- Pydantic/serializer models used to constrain input shape (FastAPI) rather than accepting raw dicts

**If C, C++, or Rust with `unsafe` blocks detected**, additionally check (per current CWE Top 25 — memory safety weaknesses rank #5, #7, #8, #11, #14, #16):
- Buffer bounds checked before write/read operations (Out-of-bounds Write CWE-787 and Read CWE-125 rank #5 and #8)
- Use-after-free patterns: freed memory/pointers never accessed afterward (CWE-416, #7)
- Buffer copy operations use size-checked variants, never raw `strcpy`/`memcpy`-style calls without a length bound (CWE-120/121/122)
- Rust `unsafe` blocks are minimal, individually justified with a comment explaining the invariant being upheld, and not used to bypass the borrow checker for convenience

**If the project exposes a REST/GraphQL API as its primary interface**, additionally check against OWASP API Security Top 10:2023:
- **API3:2023 — Broken Object *Property* Level Authorization**: distinct from BOLA (Category 1) — this is about individual *fields* in a response/request being exposed or mass-assignable, not just whole-object access. Check serializers/response DTOs for over-exposed fields (e.g. returning a full user object including internal fields when only `name`/`email` should be public).
- **API4:2023 — Unrestricted Resource Consumption**: rate limiting tied specifically to cost — if the API triggers billable third-party actions (SMS, email, biometric checks, LLM calls), confirm there's a cap preventing abuse from becoming a real financial cost, not just a generic rate limiter.
- **API6:2023 — Unrestricted Access to Sensitive Business Flows**: can a legitimate flow (ticket purchase, coupon redemption, comment posting) be automated/scripted at scale to harm the business, even without any implementation bug? This is a business-logic-level check, not a code-bug check.
- **API9:2023 — Improper Inventory Management**: are old/deprecated API versions still live and reachable? Are there "shadow" or forgotten test/internal endpoints exposed in production that aren't in the current API documentation?
- **API10:2023 — Unsafe Consumption of APIs**: does this project blindly trust responses from third-party APIs it calls (payment gateways, partner integrations)? Validate and sanitize third-party API responses the same way user input would be validated — a compromised upstream API is still an untrusted input source.
- Rate limiting present on public/unauthenticated endpoints; pagination/limit enforced on list endpoints to prevent resource exhaustion

**If the project has an AI/LLM/agentic feature** (any LLM SDK, agent framework, or tool-calling capability), additionally check against OWASP Top 10 for LLM Applications 2025:
- **LLM01 — Prompt Injection** (the #1 risk for two consecutive editions): any user input or fetched external content (emails, web pages, documents, tool results) that reaches a system prompt or tool-calling context without a clear trust boundary between "instructions" and "data." Indirect prompt injection via retrieved/fetched content is as real a risk as direct user input.
- **LLM02 — Sensitive Information Disclosure**: could the model be tricked into revealing training data, system prompt contents, or another user's session/context data in its output?
- **LLM03 — Supply Chain**: are third-party models, fine-tunes, LoRA adapters, or plugins pulled from trusted, verified sources, not arbitrary community uploads with no provenance check?
- **LLM04 — Data and Model Poisoning**: if the project fine-tunes or trains on any user-contributed or externally-sourced data, is that data pipeline protected against injection of poisoned training examples?
- **LLM05 — Improper Output Handling**: is LLM-generated output ever passed downstream (rendered as HTML, executed as code, used to construct a database query or shell command) without the same validation/sanitization that would apply to raw user input? Treat LLM output as untrusted input to the next system, not as trusted application logic.
- **LLM06 — Excessive Agency**: does the AI feature have the ability to take real-world, irreversible actions (send emails, make payments, delete data, call external APIs) without a human-in-the-loop confirmation step? Check the three root causes explicitly: excessive *functionality* (more tools than the task needs), excessive *permissions* (broader scope than necessary), excessive *autonomy* (no approval gate on high-impact actions).
- **LLM07 — System Prompt Leakage** (new for 2025): does the system prompt contain secrets, credentials, internal business logic, or instructions that would be damaging if extracted by the end user? Assume the system prompt WILL eventually leak — never put anything in it that can't survive being read by the user.
- **LLM08 — Vector and Embedding Weaknesses** (if RAG/vector search is used): are vector stores access-controlled per-tenant, preventing cross-tenant data leakage via similarity search? Is there any validation preventing malicious content from being injected into the vector store to be retrieved and trusted later?
- **LLM09 — Misinformation**: if the application makes or informs real decisions based on LLM output (medical, legal, financial, or otherwise consequential), is there a human review step, or is hallucinated output capable of causing real harm unchecked?
- **LLM10 — Unbounded Consumption**: are there hard limits on LLM call frequency, token usage, and context size per user/session, to prevent both cost-abuse and denial-of-service via resource exhaustion?

**If a mobile stack is detected** (React Native, Flutter, native iOS/Android, Xamarin/MAUI, Cordova/Ionic), additionally check against OWASP Mobile Top 10:2024 — the first major revision since 2016, reflecting the current mobile threat landscape:
- **M1 — Improper Credential Usage** (#1 risk, consistent top finding across mobile pentests for years): grep decompiled/bundled output and source for hardcoded API keys, OAuth secrets, AWS credentials, or any credential baked into the binary. Secrets must be fetched at runtime from a server, or at minimum use platform secure storage (Keychain/Keystore) — never embedded directly in app code or resource files, since APKs/IPAs are trivially decompiled.
- **M2 — Inadequate Supply Chain Security**: third-party SDKs, native modules, and build tooling reviewed the same way server-side dependencies are (Category 3 above) — a malicious or compromised mobile SDK has direct access to device data and user sessions.
- **M3 — Insecure Authentication/Authorization**: session tokens, biometric auth implementations, and OAuth flows validated server-side, not just gated by a client-side check that can be bypassed via a patched/rebuilt APK.
- **M4 — Insufficient Input/Output Validation**: the mobile client is not a trusted validation boundary — every input validated client-side must also be validated server-side, since a modified client can send anything.
- **M5 — Insecure Communication**: TLS enforced for all network calls, certificate/public-key pinning considered for high-sensitivity apps, no sensitive data sent over unencrypted channels.
- **M6 — Inadequate Privacy Controls**: PII and sensitive data collection minimized, user consent obtained appropriately, no unnecessary data (contacts, location, device identifiers) collected beyond what the feature actually requires.
- **M7 — Insufficient Binary Protections**: for apps handling sensitive data/transactions, consider code obfuscation, anti-tampering, and root/jailbreak detection as defense-in-depth — informational for low-sensitivity internal tools, Important for financial/health/high-value-target apps.
- **M8 — Security Misconfiguration**: platform-specific config (Android manifest permissions, iOS entitlements, debug flags, exported components/activities) reviewed for anything broader than the app actually needs.
- **M9 — Insecure Data Storage**: no sensitive data (tokens, PII, cached credentials) stored in plaintext in local storage, shared preferences, or unencrypted local databases — use platform-provided encrypted storage APIs.
- **M10 — Insufficient Cryptography**: same cryptographic standards as Category 4 above apply on-device — no weak/custom crypto implementations, proper key storage via platform secure enclaves where available.

## Overlap rule — one finding, one primary category

Some vulnerabilities legitimately span multiple categories in this checklist (e.g. SSRF touches both Category 1 Broken Access Control and API10:2023 Unsafe Consumption of APIs; XSS touches both Category 5 Injection and, if LLM-generated, LLM05 Improper Output Handling). Do not report the same finding twice under two headings — that inflates the count and makes the summary misleading.

Rule: file each finding once, under its most specific applicable category, using this precedence:
1. A stack-specific category (Laravel, API, LLM, Mobile, memory-safety) beats a universal category, if the finding is specific to that stack's named risk (e.g. an SSRF via a webhook URL field in an API-first project files under API10, not the generic Category 1 SSRF bullet).
2. If no stack-specific category applies, file under the most specific universal category (a file-upload RCE files under Category 11 File Handling, not the generic Category 5 Injection, even though code execution is technically an injection outcome).
3. If genuinely ambiguous between two universal categories, file under the lower-numbered (higher OWASP-ranked) one and add a one-line cross-reference note in the other category's section ("see Category 1, finding #3 — also relevant here").

This rule exists so the summary table's issue count reflects distinct vulnerabilities, not the same bug counted once per category it happens to touch.

## Completion checklist — mandatory before the report is considered done

Before presenting the final Summary, explicitly confirm coverage of every applicable category. This exists because a long checklist invites silent skipping under time pressure — the point of this section is to make that impossible to do quietly.

Produce this table as the last thing before the Summary, listing every category that applied to the detected stack (universal 1–13 always apply; stack-specific sections apply only when Step 0 detected that stack):

```
Coverage Checklist
Category                                  | Checked | Findings
1. Broken Access Control                  | ✅/⬜   | N
2. Security Misconfiguration              | ✅/⬜   | N
3. Software Supply Chain Failures         | ✅/⬜   | N
4. Cryptographic Failures                 | ✅/⬜   | N
5. Injection                              | ✅/⬜   | N
6. Insecure Design                        | ✅/⬜   | N
7. Authentication Failures                | ✅/⬜   | N
8. Software or Data Integrity Failures    | ✅/⬜   | N
9. Security Logging and Alerting Failures | ✅/⬜   | N
10. Mishandling of Exceptional Conditions | ✅/⬜   | N
11. File Handling                         | ✅/⬜   | N
12. Business Logic Flaws                  | ✅/⬜   | N
13. Infrastructure & Deployment           | ✅/N/A  | N
[Stack-specific sections that applied, same format]
```

`⬜` (unchecked) is not an allowed final state — every row must resolve to `✅` (checked, findings counted, possibly zero) or `N/A` (category doesn't apply to this project type, e.g. Infrastructure & Deployment with no IaC present, or Mobile with no mobile stack detected). If a row is still `⬜` when the review is otherwise "done," go back and actually check it before presenting the report — do not mark something `N/A` simply to close it out faster.

## Output format

```
Security Review — [Project/Feature Name]
Detected stack: [e.g. "Laravel 12 (PHP), Vite/vanilla JS frontend"]
Scope: [full project | diff against branch/commit X]

Category 1 — Broken Access Control
[PASS or ISSUES FOUND, with severity tags]

Category 2 — Security Misconfiguration
...

[continue for all 13 universal categories, then any applicable stack-specific findings folded into the relevant category]

Coverage Checklist
[the mandatory table described above — every applicable category marked ✅ or N/A, none left ⬜]

Summary
N distinct issues found across N categories (deduplicated per the overlap rule above).
# | Severity | Category | File:Line | Issue | Fix
Resolve Critical and Important before [deploy/next feature]. Minor items can be addressed now or deferred.
```

Severity definitions:
- **Critical** — actively exploitable, would cause real harm if shipped (data breach, auth bypass, RCE, payment manipulation)
- **Important** — a real weakness that should be fixed before production, not immediately exploitable but a clear risk
- **Minor** — best-practice gap, low real-world risk, worth fixing but not blocking

Severity is contextual to exposure, not just the abstract vulnerability class. The same vulnerability class can warrant different severities depending on who can reach it:
- A finding reachable by any unauthenticated internet user is generally more severe than the identical code pattern reachable only by an already-authenticated internal admin, which is in turn more severe than one reachable only by a superuser/developer with direct server access.
- State the reachability explicitly in each finding ("reachable by any unauthenticated visitor" vs. "requires an already-compromised admin session") rather than assigning severity from the vulnerability class alone. A textbook-Critical vulnerability class sitting behind three layers of legitimate access control may reasonably be filed as Important, not Critical — say why.
- Do not silently downgrade severity to make a report look better; state the reasoning so the reader can disagree.

Where possible, cite the exact file and line, and show the vulnerable snippet alongside a corrected version — a finding without a concrete fix path is less actionable and should be avoided.

## Rules

- Always run Step 0 first and state the detected stack explicitly before any findings
- Never skip a universal category because "this feature doesn't touch that" — state explicitly why a category is N/A rather than omitting it
- Only apply stack-specific checks for stacks actually detected in the project — don't run Laravel checks against a Node project, don't run AI/LLM checks against a project with no LLM feature, don't run mobile checks against a pure web backend
- Always check actual code, never assume based on variable/method/file naming alone
- Grep-based checks are a starting point, not a substitute for reading the actual logic — a grep hit is a lead to investigate, not itself a finding
- If a Critical finding is discovered, flag it immediately and prominently — don't bury it in a long list
- This skill does not fix issues automatically — it reports findings, exactly like `/review`, and waits for explicit instruction on which to fix
- This skill is for defensive/authorized review of code you own or are authorized to assess. It is not an offensive penetration-testing or exploit-development tool, and should not be used against systems without authorization.
- This skill is aligned to standards current as of mid-2026: OWASP Top 10:2025, OWASP API Security Top 10:2023, OWASP LLM Top 10:2025, OWASP Mobile Top 10:2024, CWE Top 25:2025. OWASP updates its web Top 10 roughly every 3-4 years and CWE publishes annually. If a future session has reason to believe a newer edition of any of these exists, verify and update this file's category mapping and CWE citations accordingly rather than assuming these editions are still current.