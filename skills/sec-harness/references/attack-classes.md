# Attack Classes

Canonical attack-class keys used across the harness. Recon selects a subset into
`attack_surface`/`agents_to_spawn`; Plan 3 spawns one investigation agent per key.
Use these exact keys (lowercase) in `scan-profile.json`.

| key | name | ripgrep indicators (non-exhaustive) | PoC feasible (no-exec harness) |
|-----|------|-------------------------------------|-------------------------------|
| `sqli` | SQL injection | `execute(`, `cursor`, `SELECT`, `%`/f-string into query, ORM raw | static only |
| `cmdi` | OS command injection | `subprocess`, `os.system`, `exec(`, `child_process`, backticks (note: `exec(` substring-matches PHP `curl_exec(`/`mysqli_*_exec` — anchor with word boundary `\bexec\(` or `\bshell_exec\(` to avoid HTTP/DB false hits) | static only |
| `ssrf` | Server-side request forgery | `requests.get(`, `urlopen`, `fetch(`, `axios`, user-controlled URL | static only |
| `path-traversal` | Path traversal / file read-write | `open(`, `join(`, `../`, `send_file`, `readFile` | static only |
| `fileupload` | Insecure file upload | `multer`, `request.FILES`, `req.files`, `MultipartFile`, `move_uploaded_file`, `FormFile`, extension/content-type checks on upload path | static only |
| `authz` | Broken access control (BOLA/BFLA) | route handlers, `current_user`, missing role checks, IDs in path | static only |
| `authn` | Authentication flaws | `login`, `session`, `jwt`, `password`, token verification | static only |
| `deserialization` | Unsafe deserialization | `pickle`, `yaml.load`, `Marshal`, `readObject`, `eval(` | static only |
| `xss` | Cross-site scripting | template render, `innerHTML`, `dangerouslySetInnerHTML`, unescaped output | static only |
| `secrets` | Hardcoded secrets/keys | `api_key`, `secret`, `AKIA`, `sk_live_`, `token =`, private keys | static only |
| `crypto` | Weak/misused cryptography | `md5`, `sha1`, `DES`, `ECB`, static IV, `random` for tokens | static only |
| `ssti` | Server-side template injection | template engine with user input, `render_template_string` | static only |
| `xxe` | XML external entity | XML parser without entity disabling, `etree`, `DocumentBuilder` | static only |
| `open-redirect` | Open redirect | `redirect(`, user-controlled `Location`, `next=` params | static only |
| `deps` | Vulnerable dependencies | lockfiles / manifests (handled by SCA, not an investigation agent) | static only |
| `prompt-injection` | LLM prompt injection / unsafe tool use / guardrail bypass | `langchain`, `langgraph`, `openai`, `anthropic`, `bedrock`, `.invoke(`, `bind_tools`, `mcp`, tool registration, user text → model prompt, model output → sink (exec/DB/fetch) | static only |
| `webhook-verification` | Missing/incorrect signature verification | `X-Shopify-Hmac-Sha256`, `Stripe-Signature`, `verifyWebhook`, `crypto.timingSafeEqual`, `hmac`, raw-body handling on a webhook/callback route | static only |
| `expr-eval-rce` | Sandboxed expression/rule-engine escape | `jsep`, `expr-eval`, `mathjs`, `vm.runInContext`, `callee.apply`, `constructor.constructor`, custom formula/rules engines | static only |

`expr-eval-rce` is distinct from `deserialization` and `ssti`: the sink is a custom
evaluator's own call/apply mechanism, not `eval()` or a template engine.

## Selection guidance for recon

- Include a class in `attack_surface` only when at least one indicator is present
  OR a framework strongly implies it (e.g. any web framework → consider `authz`,
  `xss`, `open-redirect`). Empty evidence → omit; do not spawn agents for classes
  with no surface (this is the primary token saver).
- **LLM / agent apps** (LangChain/LangGraph/Bedrock/MCP): select `prompt-injection`
  when untrusted input reaches a model prompt or the model can call tools. Map the
  agent/tool/prompt data flow in the architecture KB even though it is a newer class.
- **Webhook/callback endpoints** (Shopify/Stripe/etc.): select `webhook-verification`
  when a route consumes a signed payload; the check to hunt is HMAC/`timingSafeEqual`
  over the raw body, missing or non-constant-time.
- **Template languages that SAST cannot parse** (Liquid, Handlebars, ERB, Jinja
  used as raw strings): treat unescaped `{{ }}`/`<%= %>` output as `xss`. CodeQL is
  blind to these — the investigate agent must read templates manually and ground the
  sink with a `ripgrep:` receipt (grep proving the unescaped interpolation at
  `file:line`), which counts as a mechanical receipt.
- `agents_to_spawn` mirrors `attack_surface` MINUS `deps` (SCA covers deps).
- Everything is static-only: this harness never executes the target.
- **File upload** (`fileupload`): select when any upload-handling call is present
  (`multer`, `request.FILES`/`req.files`, `MultipartFile`, `move_uploaded_file`,
  `FormFile`, `IFormFile`). Trace guidance (no dedicated hunting doc needed — this is
  a flat checklist, not a class needing deep companion knowledge like JWT/OAuth):
  - **Vulnerable indicators**: no extension check; Content-Type/MIME-header-only
    validation (fully attacker-controlled — never a security control); extension
    blocklist missing known gaps (PHP: `.php3/.php4/.php5/.phtml/.phar/.shtml`; Java:
    `.jsp/.jspx/.jsw/.jsv`; ASP.NET: `.asp/.aspx/.ashx/.asmx/.cer/.asa`);
    case-sensitivity bypass (blocklist compared without `.lower()`/equivalent);
    double-extension (`shell.php.jpg`) combined with a server config that executes
    on the leftmost recognized extension; unsanitized original filename used
    directly in the storage path.
  - **Mitigating patterns**: allowlist of safe extensions applied case-insensitively;
    magic-byte/content validation as defense-in-depth; filename sanitization via a
    trusted library (`secure_filename`, `path.basename`, `Path.GetFileName`,
    `filepath.Base`); storage outside the web root; server-generated rename (UUID)
    so the served extension is server-controlled; serving through a controlled
    download endpoint with `Content-Disposition: attachment`.
  - **FP trap**: an allowlist alone does not clear the finding if the storage
    directory is still web-executable, the comparison is case-sensitive, or the
    extension is extracted from the wrong segment of a double-extension filename —
    the allowlist must be checked against the extension that will actually be
    served/executed, not just list membership.

## Domain-specific classes & companion knowledge (F2)

Beyond the universal classes above, target-conditional companion docs under
`references/hunting/` carry deeper class-by-class hunting guidance. Recon selects the
relevant companions by detected frameworks/target type and records them in
`scan-profile.json` `notes.hunting_docs`; investigate/threat-model import them alongside
`hunting/methodology.md` (12 attacker-mindset heuristics) and `hunting/anti-patterns.md`
(10 auditor failure modes).

| companion doc | added classes (keys) |
|---------------|----------------------|
| `hunting/web-protocol-auth.md` | `jwt`, `oauth-oidc`, `saml`, `request-smuggling`, `cache-poisoning` |
| `hunting/client-side.md` | `dom-xss`, `dom-clobbering`, `cswsh`, `prototype-pollution`, `open-redirect-client` |
| `hunting/ai-agent.md` | `excessive-agency`, `denial-of-wallet`, `mcp-trust-inheritance`, `context-bleed`, `prompt-injection` |
| `hunting/business-logic.md` | `business-logic`, `feature-abuse`, `chained` |
| `hunting/graphql-injection.md` | `graphql` |
| `hunting/memory-native.md` | `spatial-oob`, `temporal-uaf`, `type-confusion` (only when native/unsafe code is present) |

Selection guidance: choose a companion when its frameworks/indicators appear (JWT/OAuth/
SAML libs → web-protocol-auth; browser/DOM/React → client-side; LangChain/LangGraph/MCP →
ai-agent; always consider business-logic; memory-native only for C/C++/unsafe; GraphQL
libraries (`graphql`, `apollo-server`, `graphql-yoga`, `@nestjs/graphql`, `graphene`,
`strawberry-graphql`, `gqlgen`, `async-graphql`) or a `.graphql`/`.graphqls` schema file
→ graphql-injection). Companion
classes flow through `agents_to_spawn` + `clsmap` exactly like universal ones.

## Class disambiguation (cross-class boundary discipline)

Classes above with a thin extension in `agents/classes/*.md` carry a full "Class boundary"
section (IS / IS NOT / route-to). For the remaining canonical keys that have no extension
file yet, use this table to route a confused shape to the right `cls` instead of
force-fitting it into whichever agent happened to find it:

| Confusable pair | Discriminator |
|-----------------|---------------|
| `ssti` vs `xss` | Does the payload execute as TEMPLATE syntax server-side (`{{ }}`/`<%= %>` evaluated by the template engine) → `ssti`. Does it render unescaped into HTML/DOM with no server-side template evaluation → `xss`. |
| `ssti` vs `deserialization`/`cmdi` | SSTI's sink is a template engine's own render call, not `eval()`/`pickle.loads()`/`exec()` — those are `deserialization`/`cmdi` even if the exploit chain ultimately achieves code execution through a template engine's escape hatch. |
| `xxe` vs `deserialization` | XXE is specifically an XML parser expanding external entities (DTD/`SYSTEM`); a non-XML deserializer (pickle, YAML, Java `readObject`) is `deserialization` even though both can reach file-read/RCE. |
| `path-traversal` vs `resource` | Impact is arbitrary file read/write outside the intended root → `path-traversal`. Impact is exhaustion from unbounded size/count with no traversal → `resource`. |
| `fileupload` vs `path-traversal` | A traversal-in-filename bug (`../../webroot/shell.php` used unsanitized in the storage path) reuses `path-traversal`'s classic pattern in an upload context. Route to `fileupload` when the finding is about WHAT gets stored/executed (extension/content-type bypass enabling a webshell); route to `path-traversal` when the finding is purely about WHERE the write lands outside the intended root, with no execution angle. |
| `open-redirect` vs `ssrf` | The tainted URL is only ever handed to the BROWSER (a `Location`/redirect response) with no server-side fetch → `open-redirect`. The SERVER itself dereferences the URL → `ssrf`. |
| `webhook-verification` vs `crypto` | Missing/broken signature check on a specific inbound webhook route → `webhook-verification`. A weak algorithm/key source used more generally (not gating a webhook) → `crypto`. |
| `expr-eval-rce` vs `deserialization`/`ssti` | The sink is a custom expression/rule-engine's own call/apply mechanism (`jsep`, `expr-eval`, `mathjs`, a bespoke formula engine) — not a language-level deserializer or a template engine's render call. |
| `dom-xss`/`dom-clobbering`/`prototype-pollution` vs `xss` | Client-side-only sinks (`innerHTML`, global object pollution via crafted property names) with no server-side render step → the specific client-side key, not generic `xss`. |

If a candidate could plausibly be two of these, write it under the discriminated class and
note the other in the finding's `message` — never split one concrete sink into two findings
under both classes.
