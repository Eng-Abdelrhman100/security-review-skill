---
name: security-review
description: Framework-agnostic security audit skill. Detects the project's tech stack, then runs universal and stack-specific security checks aligned with OWASP Top 10:2025, OWASP API Security Top 10:2023, OWASP LLM Top 10:2026, OWASP Top 10 for Agentic Applications 2026, OWASP Mobile Top 10:2024, and CWE Top 25:2025. Use when reviewing code for vulnerabilities, running a security audit, pen testing, checking authentication/authorization/injection/file-upload/OAuth flows, or before a production deploy or client handoff.
when_to_use: After any feature involving auth, payments, file uploads, OAuth, or user input; before any production deploy or client handoff; on explicit trigger phrases like "security-review this", "run a security review", "audit this for vulnerabilities", "pen test this"; at least once as a full-project baseline on a new or existing codebase, then re-run scoped to the diff after major auth/integration features.
---

# /security-review

A structured, framework-agnostic security audit skill. Detects the project's tech stack first, then runs a fixed set of universal security checks plus stack-specific checks relevant to what was detected. Output format mirrors `/review` — severity-tagged findings, no automatic fixes unless explicitly requested.

Aligned with six current, independently-sourced standards — not an invented checklist:
- **OWASP Top 10:2025** (top10.owasp.org/2025) — general web application risks
- **OWASP API Security Top 10:2023** (api-security.owasp.org) — API-specific risks
- **OWASP Top 10 for LLM Applications 2026** (genai.owasp.org/resource/owasp-genai-llm-top-10-2026/, released August 4, 2026) — risks of the model as a *component* (input in, output out)
- **OWASP Top 10 for Agentic Applications 2026** (genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/, ASI01–ASI10, published December 9, 2025) — risks of the model as an autonomous *actor* (plans, holds memory, calls tools, acts with delegated authority)
- **OWASP Mobile Top 10:2024** (owasp.org/projects/mobile-top-10) — mobile app-specific risks, first major update since 2016
- **CWE Top 25:2025** (cwe.mitre.org/top25) — MITRE's real-world CVE-data-driven weakness ranking

## When to use

- After any feature involving auth, payments, file uploads, OAuth, or user input
- Before any production deploy or client handoff
- On explicit trigger: `/security-review`, "run a security review", "security-review this", "audit this for vulnerabilities", "pen test this"
- Should run at least once before go-live, and again after any major auth/integration feature
- Works on any project — Laravel, Node/Express, Django, Rails, plain PHP, React/Next.js frontends, Rust/Go/C++ backends, AI/LLM-powered features, etc.
- Diff-aware: when reviewing a specific PR/branch/recent change set, scope the review to changed files first, then note if any change touches a security-sensitive area (auth, secrets, file I/O, external calls, LLM prompts) that warrants a wider check of the surrounding code.

### Expected depth and cost

This skill is intentionally read-heavy, not grep-only. A grep hit is a lead to investigate, never itself a finding (see Rules below) — every category requires actually opening and reading the relevant files, tracing a request through middleware/policy/controller, and reasoning about real reachability before a finding is reported. This is deliberate: two independent real-world runs of this skill found genuinely serious, non-obvious issues (an unthrottled admin login with no attempt logging; a hardcoded admin backdoor route with a password visible in the HTTP response) that a shallow, pattern-matching-only pass would have missed entirely. Expect a full-project baseline scan to consume meaningfully more tool calls and tokens than a typical feature build or `/review` pass — that cost is the mechanism by which this skill finds real vulnerabilities, not overhead to be trimmed. Do not shorten investigation depth to save tokens; if budget is genuinely constrained, reduce scope (diff-scoped instead of full-project) rather than reducing thoroughness within whatever scope is chosen.

## Step 0 — Detect the stack

Before checking anything, identify what's actually in the project. Look for, in order:

- `composer.json` → PHP project. Check `require` for `laravel/framework`, `symfony/*`, or plain PHP.
- `package.json` → Node project. Check `dependencies`/`devDependencies` for `next`, `express`, `react`, `vue`, `@angular/core`, etc.
- `requirements.txt` / `pyproject.toml` → Python. Check for `django`, `flask`, `fastapi`.
- `Gemfile` → Ruby. Check for `rails`.
- `go.mod` → Go.
- `Cargo.toml` → Rust. Note ownership/unsafe-block boundaries if present.
- Memory-unsafe languages present (C, C++, and unsafe Rust blocks) → also run the Memory Safety checks under Category 5 (Injection/CWE crossover) below — these languages carry real weight in the current CWE Top 25 (Use After Free, Out-of-bounds Read/Write, Buffer Overflows all rank in the top 16).
- Any LLM/AI SDK present (`openai`, `anthropic`, `@anthropic-ai/sdk`, `langchain`, `llamaindex`, `google-genai`, etc.) → also run the AI/LLM stack-specific checks (OWASP LLM Top 10:2026) in Step 2.
- **Autonomous agentic feature present** — a separate trigger from the LLM/AI SDK one above, and additive to it. Fires when the model does not just return text but *acts*: an agent framework or loop with tool/function calling that executes real side effects, persistent memory across sessions, and/or autonomous multi-step action without a human approving each step. Signals: `langgraph`, `crewai`, `autogen`/`ag2`, `openai-agents`/`@openai/agents`, `claude-agent-sdk`/`@anthropic-ai/claude-agent-sdk`, `semantic-kernel`, `llama-index` agent modules, `smolagents`, `pydantic-ai`, MCP server/client code (`@modelcontextprotocol/sdk`, `mcp`), a hand-rolled `while` loop that feeds tool results back to the model, vector/KV stores used as agent long-term memory, or agent-to-agent messaging. → also run the Autonomous Agentic checks (OWASP Agentic Top 10 2026) in Step 2.
  - **Distinguishing the two triggers**: a chatbot, summarizer, classifier, or RAG Q&A endpoint that only returns text to the user is **LLM-only** — run the LLM section, mark Agentic `N/A` with the reason. The moment the model's output selects and invokes a tool that changes state (writes files, sends messages, calls APIs, runs code, spends money), persists memory it will later trust, or runs multi-step without per-step approval, it is **agentic** — run both sections. When in doubt, trace one request: if any model-chosen action executes without a human seeing the exact action first, treat it as agentic.
  - Note that the environment running this skill (Claude Code or a similar agentic coding tool) is itself an agentic system — repo config that steers such tools (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.claude/settings.json`, `.mcp.json`, hooks, custom skills/agents) is agentic attack surface and falls under the Agentic section even in an otherwise non-AI project.
- Any API-first project (REST/GraphQL endpoints as the primary interface, OpenAPI/Swagger spec present) → also run the API-specific checks in Step 2 with extra weight, since these are validated against a dedicated OWASP list.
- Mobile stack present (`android/` + `ios/` dirs, `pubspec.yaml` for Flutter, `.xcodeproj`/`Podfile` for native iOS, `build.gradle` for native Android, React Native's `metro.config.js`, Xamarin/MAUI `.csproj`, or Cordova/Ionic `config.xml`) → also run the Mobile-specific checks in Step 2.
- Infrastructure-as-code present (`Dockerfile`, `*.tf`, `k8s/*.yaml`, `docker-compose.yml`) → also run the Infrastructure & Deployment category below.
- Multiple of the above → treat as a multi-stack project (e.g. Laravel backend + separate JS frontend + LLM feature) and run checks against each part separately, scoped to the relevant directory.
- **Multiple genuinely separate sub-projects** (not just multiple stacks within one app, but distinct deployable applications living in the same repository — e.g. a main app plus a separate LMS/admin/microservice sub-app each with their own `composer.json`/`package.json`, routes, and entry point) require independent, explicit coverage per sub-project. A single "Checked ✅" per category is not sufficient when two sub-projects exist — see the Coverage Checklist requirement below, which must confirm each sub-project was actually walked, not just the app as a whole.

State the detected stack explicitly at the start of the review output. If detection is ambiguous, ask rather than guessing. If multiple sub-projects are detected, list each one by name/path explicitly in the "Detected stack" line of the output.

### Parallelization for full-project scans

On a full-project baseline scan (not a small diff-scoped review), decompose the 13 universal categories plus applicable stack-specific sections into 3-4 logical groups and investigate them concurrently via sub-agents/parallel tool calls, if the runtime supports it:

- **Group A — Access, Auth, Business Logic**: Categories 1, 6 (rate-limiting portion), 7, 12
- **Group B — Injection, XSS, File Handling**: Category 5, 11, plus any stack-specific injection/upload checks
- **Group C — Config, Crypto, Supply Chain, Integrity, Logging, Exceptions**: Categories 2, 3, 4, 8, 9, 10, 13
- **Group D (if applicable)** — any large stack-specific section (API, LLM, Agentic, Mobile) that's substantial enough to warrant its own pass

Each group should be given the same file:line citation, severity, and "CLEAN because I checked X" requirements as a single-pass review. This scales investigation depth on large codebases without any one pass running out of context, and was validated as effective on a real ~25-controller Laravel project. For a small diff-scoped review (a handful of changed files), a single sequential pass is simpler and sufficient — don't parallelize trivially small reviews.

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

**If the project has an AI/LLM feature** (any LLM SDK — see Step 0), additionally check against OWASP Top 10 for LLM Applications 2026:

> **What changed from 2025.** Released August 4, 2026 at Black Hat USA, superseding the 2025 edition. Eight of ten entries moved and one was renamed: Excessive Agency rose #6→#3 (biggest mover), Unbounded Consumption #10→#6, Misinformation #9→#7; Supply Chain fell #3→#4, Data and Model Poisoning #4→#5, Vector and Embedding Weaknesses #8→#9, and Improper Output Handling fell sharply #5→#10. System Prompt Leakage (#7) was renamed **Hidden Context Exposure** (#8) with a widened scope. **Methodology changed too**: rankings are now 75% practitioner consensus + 25% weighted by 6,639 real-world incidents (public vulnerability databases and an AI-harm database) — the first edition where incident evidence, not opinion alone, shaped the order. The 2026 edition also scopes itself explicitly to the model as a *component*; once the model becomes an actor with tools and memory, the risk moves to the Agentic Top 10 section below. A fall in rank means lower observed incident weight, not that the risk is solved — every entry still gets checked.

- **LLM01:2026 — Prompt Injection** (unchanged #1): any user input or fetched external content (emails, web pages, documents, tool results) that reaches a system prompt or tool-calling context without a clear trust boundary between "instructions" and "data." Indirect prompt injection via retrieved/fetched content is as real a risk as direct user input. Design on the assumption the model *will* be fooled — the fix is containment around the model, not a prompt that claims to be un-foolable.
- **LLM02:2026 — Sensitive Information Disclosure** (unchanged #2): could the model be tricked into revealing training data, context contents, or another user's session/context data in its output? Check that per-user data is never placed in a shared context, cache, or conversation history reachable by another user.
- **LLM03:2026 — Excessive Agency** (up from #6): does the AI feature have the ability to take real-world, irreversible actions (send emails, make payments, delete data, call external APIs) without a human-in-the-loop confirmation step? Check the three root causes explicitly: excessive *functionality* (more tools than the task needs), excessive *permissions* (broader scope than necessary), excessive *autonomy* (no approval gate on high-impact actions). If this finding exists, the feature almost certainly also triggers the Agentic section below — see the overlap rule for where to file it.
- **LLM04:2026 — Supply Chain** (down from #3): are third-party models, fine-tunes, LoRA adapters, or plugins pulled from trusted, verified sources, not arbitrary community uploads with no provenance check? Model files loaded via unsafe formats (`pickle`-based `.pt`/`.bin`) are also a CWE-502 deserialization risk — prefer `safetensors`.
- **LLM05:2026 — Data and Model Poisoning** (down from #4; now also absorbs fine-tuning subversion): if the project fine-tunes or trains on any user-contributed or externally-sourced data, is that data pipeline protected against injection of poisoned training examples? Are fine-tuning jobs and their datasets access-controlled so an attacker cannot subvert the tuned model?
- **LLM06:2026 — Unbounded Consumption** (up from #10; now explicitly includes **Denial of Wallet**): are there hard limits on LLM call frequency, token usage, output length, and context size per user/session/tenant? Check for a per-account spend cap or budget alarm, not just a request-rate limiter — an attacker who can make the app burn paid tokens (long prompts, recursive/looping calls, forced max-length output) causes real financial damage without ever taking the service down. Also covers service disruption and model extraction via high-volume querying.
- **LLM07:2026 — Misinformation** (up from #9): if the application makes or informs real decisions based on LLM output (medical, legal, financial, or otherwise consequential), is there a human review step, source grounding/citation, or confidence gating — or is hallucinated output capable of causing real harm unchecked?
- **LLM08:2026 — Hidden Context Exposure** (renamed from System Prompt Leakage, was #7; scope widened): covers **all non-user-facing context**, not just the system prompt — developer instructions, retrieved policy text, tool schemas/descriptions, workflow rules and decision criteria, and any hidden RAG chunks. Does any of it contain secrets, credentials, internal endpoints, or business logic that would be damaging or would enable further attacks if the user extracted it? Assume all hidden context WILL eventually leak — never put anything in it that can't survive being read by the user, and enforce authorization in code, never via instructions in the context.
- **LLM09:2026 — Vector and Embedding Weaknesses** (down from #8; if RAG/vector search is used): are vector stores access-controlled per-tenant, preventing cross-tenant data leakage via similarity search? Is there any validation preventing malicious content from being injected into the vector store to be retrieved and trusted later?
- **LLM10:2026 — Improper Output Handling** (down sharply from #5): is LLM-generated output ever passed downstream (rendered as HTML, executed as code, used to construct a database query or shell command) without the same validation/sanitization that would apply to raw user input? Treat LLM output as untrusted input to the next system, not as trusted application logic. The low rank reflects incident weighting, not reduced severity — an XSS or SQLi via model output is still Critical when reachable.

**If the project has an autonomous agentic feature** (the separate agentic trigger in Step 0 — tool calling with real side effects, persistent memory, or autonomous multi-step action), additionally check against the OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10). Run this *in addition to* the LLM section above, not instead of it.

> **Why a separate layer.** Published December 9, 2025 by the OWASP GenAI Security Project. The LLM Top 10 treats the model as a component that receives input and produces output; the Agentic Top 10 treats it as an autonomous *actor* that plans, holds memory, calls tools, and acts with delegated authority — so a single fooled decision becomes a real-world action. It is built from real 2025 incidents: **EchoLeak** (CVE-2025-32711, zero-click prompt injection against Microsoft 365 Copilot exfiltrating data via content the agent read), the **Amazon Q Developer** compromise (a malicious commit weaponized a coding assistant extension with 950,000+ installs), and **Replit's agent deleting a production database** during an explicit code freeze. This is not hypothetical for this skill's own use case: it is typically run *by* an agentic coding tool.

- **ASI01 — Agent Goal Hijack**: an attacker redirects the agent's objective through content it *reads* (emails, tickets, web pages, PR descriptions, documents, tool output), not code it runs. Check: is untrusted content clearly separated from instructions and never able to change the task, the tool set, or the recipient of an action? Is the agent's goal/plan fixed by the trusted caller and re-validated before high-impact steps? Mitigation: treat all ingested content as data; constrain the action space per task so a hijacked goal still can't reach dangerous tools; require intent confirmation when the plan deviates from the original request.
- **ASI02 — Tool Misuse & Exploitation**: legitimate tools bent toward illegitimate outcomes via deceptive input or unsafe tool *chaining* (e.g. `read_file` → `http_post` = exfiltration; `search` → `delete`). Check: does each tool validate its own arguments server-side (paths, URLs, recipients, amounts) rather than trusting the model? Are dangerous tool combinations blocked or gated? Mitigation: least-functionality tool sets per task, strict argument schemas and allow-lists, egress restrictions on network tools, rate/budget limits per tool, and approval gates on destructive or outbound actions.
- **ASI03 — Identity & Privilege Abuse**: borrowed, shared, or long-lived credentials mean a hijacked agent inherits everything the agent can touch. Check: does the agent run under its own scoped identity, or with a human's/admin's token, a shared service account, or a long-lived API key in env vars? Are actions performed *on behalf of* a user authorized against that user's permissions (no confused deputy)? Mitigation: per-agent, per-task, short-lived, least-privilege credentials; on-behalf-of token exchange; never grant the agent more than the invoking user has; credentials never placed in the model's context.
- **ASI04 — Agentic Supply Chain Vulnerabilities**: components discovered or loaded at **runtime** — MCP servers, plugins, tool registries, remote prompt templates, agent cards, skills, downloaded model/agent configs — are invisible to classic dependency scanning (Category 3 lockfile audits won't see them). Check: where does the agent load tools/servers/prompts from, are they pinned by version and hash, from an allow-listed source, and is a changed tool description (tool-poisoning / "rug pull") detected? Check repo files that steer agentic coding tools (`.mcp.json`, `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, hooks, skill/agent definitions) for injected instructions or unexpected servers. Mitigation: allow-list and pin runtime components, verify signatures/provenance, review tool descriptions as code, sandbox third-party tools.
- **ASI05 — Unexpected Code Execution (RCE)**: natural language becoming running code outside intended boundaries — code-interpreter tools, generated shell/SQL/scripts, `eval` of model output, package installs the agent decides to run. Check: does model-generated code execute on the host or in an isolated sandbox (container/VM/WASM with no host mounts, no secrets, restricted network)? Can the agent install packages or modify its own tools/config? Mitigation: always sandbox execution, deny network and filesystem by default, time/resource limits, and human approval before executing generated code outside the sandbox.
- **ASI06 — Memory & Context Poisoning**: false information or instructions planted in persistent memory (long-term memory stores, vector memory, conversation summaries, shared scratchpads) — the payoff arrives sessions or weeks later, detached from the original attack. Check: who and what can write to agent memory, is memory scoped per user/tenant, is provenance recorded per entry, and is recalled memory treated as untrusted data rather than instructions? Mitigation: write validation and provenance tagging, per-tenant isolation, expiry/TTL, and the ability to audit and roll back memory.
- **ASI07 — Insecure Inter-Agent Communication** (applies **only to multi-agent systems** — no equivalent in the LLM Top 10; mark `N/A` for single-agent designs): are messages between agents (orchestrator↔worker, A2A, message buses) authenticated, integrity-protected, and authorized? Can a spoofed or compromised agent inject instructions into another agent, or replay/tamper with messages? Mitigation: mutual authentication (mTLS or signed messages), per-agent identity, schema-validated message formats, and treating peer-agent output as untrusted input.
- **ASI08 — Cascading Failures**: one bad decision (hallucination, poisoned input, hijack) propagates through every workflow and downstream agent trusting the affected agent. Check: are there validation checkpoints between steps/agents, or does each stage blindly trust the previous one? Is there a blast-radius limit? Mitigation: independent verification at trust boundaries, circuit breakers and kill switches, per-run action/spend caps, and the ability to halt and roll back a whole workflow.
- **ASI09 — Human-Agent Trust Exploitation**: targets the human approval step itself — the agent's own summary or explanation hides or misrepresents the real action (approve "clean up temp files" that is actually `rm -rf` on production), or users are trained into rubber-stamping by approval fatigue. Check: does the approval UI show the *exact, raw* action (full command, recipient, amount, diff) generated independently of the model's narrative, not only the model's description of it? Mitigation: render approvals from the actual tool call parameters, highlight destructive/irreversible operations distinctly, avoid bulk "approve all," and require step-up confirmation for high-impact actions.
- **ASI10 — Rogue Agents**: an agent operating outside policy while still appearing legitimate — its defining trait is **persistence** (it keeps acting, re-spawns, schedules itself, or survives across sessions after compromise or misalignment). Check: is there an inventory of running agents and their scheduled jobs/triggers, behavioral monitoring against expected policy, and a reliable way to revoke an agent's credentials and terminate it? Mitigation: full action audit logs tied to agent identity, anomaly detection on agent behavior, kill switch plus credential revocation, and no ability for an agent to create persistence (cron jobs, webhooks, new agents) without human approval.

Replit-style failures map directly: an agent with production write credentials (ASI03), no enforced code-freeze gate (ASI02/ASI09), and no rollback path (ASI08). When a review finds one of these, check the other two before closing the finding.

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

Some vulnerabilities legitimately span multiple categories in this checklist (e.g. SSRF touches both Category 1 Broken Access Control and API10:2023 Unsafe Consumption of APIs; XSS touches both Category 5 Injection and, if LLM-generated, LLM10:2026 Improper Output Handling; Excessive Agency touches both LLM03:2026 and ASI02/ASI03). Do not report the same finding twice under two headings — that inflates the count and makes the summary misleading.

Rule: file each finding once, under its most specific applicable category, using this precedence:
1. A stack-specific category (Laravel, API, LLM, Agentic, Mobile, memory-safety) beats a universal category, if the finding is specific to that stack's named risk (e.g. an SSRF via a webhook URL field in an API-first project files under API10, not the generic Category 1 SSRF bullet). Between the LLM and Agentic sections, a finding that involves the agent *acting* (tool call, credential use, memory write, autonomous step) files under the matching ASI category; a finding about model input/output alone files under the LLM category.
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

**If Step 0 detected multiple genuinely separate sub-projects** (distinct deployable apps in one repo, not just multiple stacks in one app), the Coverage Checklist must additionally confirm per-sub-project coverage, not just per-category. Either:
- Produce one Coverage Checklist table per sub-project, or
- Add a sub-project confirmation column/note to each row (e.g. "✅ (both mrreda/ and darsonline/ walked)" rather than a bare "✅") — a finding that exists only in one sub-project must not create false confidence that the sibling sub-project received equivalent scrutiny for that category.

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
- **Info** — worth noting for the reader's awareness, but carries no actual risk on its own (e.g. "no CORS config exists, confirm this is intentional for a same-origin app" — not a misconfiguration, just something to consciously confirm). Use sparingly — most findings should resolve to one of the three risk tiers above, not Info as a way to avoid committing to a severity.

Severity is contextual to exposure, not just the abstract vulnerability class. The same vulnerability class can warrant different severities depending on who can reach it:
- A finding reachable by any unauthenticated internet user is generally more severe than the identical code pattern reachable only by an already-authenticated internal admin, which is in turn more severe than one reachable only by a superuser/developer with direct server access.
- State the reachability explicitly in each finding ("reachable by any unauthenticated visitor" vs. "requires an already-compromised admin session") rather than assigning severity from the vulnerability class alone. A textbook-Critical vulnerability class sitting behind three layers of legitimate access control may reasonably be filed as Important, not Critical — say why.
- Do not silently downgrade severity to make a report look better; state the reasoning so the reader can disagree.

Where possible, cite the exact file and line, and show the vulnerable snippet alongside a corrected version — a finding without a concrete fix path is less actionable and should be avoided.

## Rules

- Always run Step 0 first and state the detected stack explicitly before any findings
- Never skip a universal category because "this feature doesn't touch that" — state explicitly why a category is N/A rather than omitting it
- **Every category or subcategory marked clean must state what was actually checked, not just "clean" alone.** The required phrasing is "CLEAN — [what was checked, e.g. grepped X pattern across Y directory, N hits, all confirmed safe because Z]" or "PASS — [same structure]." A bare "Clean." or "No issues." with no stated method is not acceptable output — the reader needs to know what was actually investigated to trust the finding, not just take the verdict on faith.
- Only apply stack-specific checks for stacks actually detected in the project — don't run Laravel checks against a Node project, don't run AI/LLM checks against a project with no LLM feature, don't run Agentic checks against a text-in/text-out LLM feature with no tool execution, memory, or autonomy (beyond the ASI04 agent-config-file check noted in Step 0), don't run mobile checks against a pure web backend
- Always check actual code, never assume based on variable/method/file naming alone
- Grep-based checks are a starting point, not a substitute for reading the actual logic — a grep hit is a lead to investigate, not itself a finding
- If a Critical finding is discovered, flag it immediately and prominently — don't bury it in a long list
- This skill does not fix issues automatically — it reports findings, exactly like `/review`, and waits for explicit instruction on which to fix
- This skill is for defensive/authorized review of code you own or are authorized to assess. It is not an offensive penetration-testing or exploit-development tool, and should not be used against systems without authorization.
- This skill is aligned to standards current as of 2026-09-27: OWASP Top 10:2025, OWASP API Security Top 10:2023, OWASP LLM Top 10:2026 (released 2026-08-04, superseding the 2025 edition — re-ranked with 25% incident weighting, System Prompt Leakage renamed Hidden Context Exposure), OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10, published 2025-12-09 — added as a sixth standard), OWASP Mobile Top 10:2024, CWE Top 25:2025. OWASP updates its web Top 10 roughly every 3-4 years and CWE publishes annually. If a future session has reason to believe a newer edition of any of these exists, verify and update this file's category mapping and CWE citations accordingly rather than assuming these editions are still current.