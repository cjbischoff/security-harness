# Detection coverage

_Generated from the live `clsmap` inventory (`sec_harness.detection_coverage`). An honest, falsifiable statement of what this harness catches and does not — not a claim to detect everything._

## Rule sources

| source | what it covers |
|--------|----------------|
| semgrep | broad pattern SAST, all languages; vendored security rulesets |
| codeql | semantic dataflow/taint (`security-extended`), compiled + go, python, javascript, java, csharp, cpp, ruby, swift
| osv-scanner (sca) | dependency CVEs from lockfiles/manifests |
| secrets (in-house) | distinctive-prefix credentials; broad via optional gitleaks |
| agent + ripgrep | SAST-blind languages (Liquid/templates) + business-logic/hunt-list |

## Vulnerability classes

| class | confidence | primary source |
|-------|-----------|----------------|
| authn | High | semgrep/codeql |
| authz | High | semgrep/codeql |
| clear-text-logging | High | semgrep/codeql |
| cmdi | High | semgrep/codeql |
| crypto | High | semgrep/codeql |
| deserialization | High | semgrep/codeql |
| log-injection | High | semgrep/codeql |
| open-redirect | High | semgrep/codeql |
| path-traversal | High | semgrep/codeql |
| secrets | High | secrets |
| sqli | High | semgrep/codeql |
| ssrf | High | semgrep/codeql |
| ssti | High | semgrep/codeql |
| xss | High | semgrep/codeql |
| xxe | High | semgrep/codeql |

## Language coverage matrix

| capability | php | python | javascript/ts | go | java | liquid/templates |
|------------|-----|--------|---------------|----|----|------------------|
| semgrep patterns | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| codeql dataflow | — | ✅ | ✅ | ✅ | ✅ | — |
| sca (deps) | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| secrets | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| agent + ripgrep (templates/logic) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

## Known limitations

- **CodeQL has no PHP support** — PHP dataflow relies on semgrep patterns only.
- **Semgrep OSS taint is single-function** — no cross-function/cross-file taint (that needs Semgrep Pro); the agentic investigate phase covers cross-function paths.
- **Liquid/Handlebars/ERB templates are SAST-blind** — no CodeQL/semgrep taint; covered by agent template reads grounded with `ripgrep:` receipts.
- **SCA/secrets need their tools** — `osv-scanner` for deps (else skipped-and-logged), optional `gitleaks` for broad secrets (in-house scanner covers distinctive tokens only).
- **Business-logic / auth-model classes are agent-found**, not rule-detected — recall depends on the threat-model hunt list, not SAST.
