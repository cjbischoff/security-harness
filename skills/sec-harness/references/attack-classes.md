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
| `hunting/memory-native.md` | `spatial-oob`, `temporal-uaf`, `type-confusion` (only when native/unsafe code is present) |

Selection guidance: choose a companion when its frameworks/indicators appear (JWT/OAuth/
SAML libs → web-protocol-auth; browser/DOM/React → client-side; LangChain/LangGraph/MCP →
ai-agent; always consider business-logic; memory-native only for C/C++/unsafe). Companion
classes flow through `agents_to_spawn` + `clsmap` exactly like universal ones.
