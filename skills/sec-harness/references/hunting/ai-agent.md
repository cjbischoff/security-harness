# Hunting: AI agent & LLM

Load this companion when recon flags a chatbot/assistant, RAG pipeline,
tool-calling agent loop, MCP server or client, or code that builds prompts from
untrusted input or acts on model output. The dangerous flow is
`untrusted text → model → capability or sink`, and the model is a confused
deputy that will carry attacker instructions across a trust boundary the
developer assumed it would respect. Use alongside `attack-classes.md` — the
transport is still HTTP, tools still hit SQL/shell/filesystem sinks, and
`authz` still applies; this file covers the model-specific layer on top.

## Core discipline

- "The model can be prompt-injected" is NOT a finding by itself. Injection that
  only affects the attacker's own session and their own output is a party
  trick. A finding requires the injection to CROSS A BOUNDARY: reach a victim's
  context, invoke a capability the requester lacks, exfiltrate data the
  requester can't see, or drive a downstream sink the attacker couldn't
  otherwise reach. Name the boundary crossed.
- The bug is in the CODE, not the model. Point at the line that grants the
  capability, trusts the output, or feeds the context — never at "the model's
  mood." Model non-determinism is an exploitability detail, not a reporting
  blocker. If the code makes the output harmless before it reaches a sink,
  there is no finding regardless of what the model can be talked into saying.
- Model output is untrusted input. Trace it to its sink with the same rigor as
  any request body — "it came from our model" is the exact assumption under
  attack.
- A guardrail PROMPT ("never reveal the system prompt", "refuse harmful
  requests") is not a security control and earns no credit as a mitigation. If
  prompt instructions are the only thing standing between the attacker and
  impact, the boundary is undefended.

## Classes

Each class below is selected independently, on its OWN evidence indicator — never as a bundle
just because the repo has an LLM/agent loop. In particular, `mcp-trust-inheritance` requires a
live MCP server/client trust boundary you can point at in code (a sub-agent spawn, an MCP
connection); the mere presence of an LLM call does not justify it.

**prompt-injection** (sub-types, all indicator: untrusted text reaching a model
context or a model-emitted argument reaching a sink)
- *Indirect (via retrieval/ingestion)*: sink/indicator — a RAG document, indexed
  page, upload, email, issue/PR body, or tool response that reaches the prompt
  context. Trace: who can write this content, and whose session does it fire
  in when retrieved? FP trap: content that reaches context but has no
  capability worth hijacking in that session is not a finding.
- *Tool-argument injection*: sink/indicator — a tool handler executing
  model-generated arguments against a real sink (SQL, shell, file path, HTTP
  fetch, another API). Trace each handler's parameters to its sink; validate
  them exactly like a request body. FP trap: arguments already validated/
  parameterized at the handler close this even though "the model produced
  them."
- *Direct injection into a privileged capability*: sink/indicator — a
  capability the assistant holds that the requesting USER does not (service
  identity, secrets in the system prompt, internal endpoints). Trace: enumerate
  capabilities the assistant has beyond the user's own, then check whether
  same-session text can steer the model into each. FP trap: if the model can
  only do what the user could already do via the UI, direct injection is not a
  finding.
- *Prompt-template/delimiter injection*: sink/indicator — untrusted input
  concatenated into the prompt without role/fencing separation. Trace: find the
  prompt-assembly code and whether untrusted spans are delimited from control
  text (fake system turn, fabricated tool result). FP trap: the finding is the
  assembly code, not "the model obeyed injected structure" — cite the
  concatenation site.

**excessive-agency** (confused-deputy — CWE-441)
- Sink/indicator: a tool call executed under the agent's own identity (service
  account, broad API key, DB superuser) rather than the requesting user's.
- Trace: does tool execution re-check the USER's permission on the SPECIFIC
  resource, or only that "the agent is allowed to call this tool"? The
  parameter-level form is IDOR-through-tools: `get_document(id)` with the ID
  filled from user text and no per-resource check.
- FP trap: a shared service credential that runs every query scoped to the
  authenticated user's ID is normal, safe architecture — not a confused deputy.
  Both halves (no per-resource check AND an action the user couldn't perform
  directly) must hold.

**denial-of-wallet**
- Sink/indicator: a model-controlled iteration/action loop with side effects
  (spend, send, delete, external API calls) and no per-action authorization or
  budget cap.
- Trace: can a single crafted request drive an expensive or irreversible loop?
  Does the impact land on the operator's bill, a shared rate/quota limit, or
  other tenants' availability?
- FP trap: a loop bounded by a hard iteration cap or per-request budget that's
  actually enforced in code (not just documented) is not this bug — verify the
  cap is checked, not merely configured.

**mcp-trust-inheritance**
- Sink/indicator: sub-agent spawn or MCP server/client connection.
- Trace: what identity and context does the sub-agent/tool server inherit —
  full session, credentials, or a broader capability set than the task needs?
  Treat a malicious/compromised MCP server's responses as indirect injection —
  it speaks directly into the model's context.
- FP trap: a sub-agent scoped to a narrower credential/task-specific context
  than the parent is not a lateral-movement primitive — verify what's actually
  passed down, not what could theoretically be passed.

**context-bleed** (cross-tenant retrieval/cache keying)
- Sink/indicator: the conversation-history/embedding/KV-prompt-cache key
  construction, and the retrieval query's tenant/ACL filter.
- Trace: is the cache/session key scoped per user, or is there a path where a
  shared key mixes tenants? For retrieval, confirm the QUERY itself applies a
  per-tenant metadata/ACL filter at query time — not just that documents carry
  a tenant field.
- FP trap: documents tagged with a tenant field but never filtered on is the
  bug; a tenant field that IS applied in the query's `WHERE`/filter clause is
  not — cite the query, not the schema.

## Validation rules

1. **Name the boundary crossed.** State exactly who the attacker is, whose
   session/identity the payload executes in, and what they get that they
   couldn't get directly. Attacker and victim as the same principal, acting
   with a capability they already have, is not a finding.
2. **For confused-deputy/excessive-agency, prove both halves.** (a) no
   per-resource check scoped to the requesting user, AND (b) the action is one
   the user could not perform through a normal authenticated request.
3. **Cite the trusting line and prove taint reaches it.** For tool-argument and
   output findings, show the concrete sink with model-influenced data reaching
   it unvalidated. For extraction/disclosure, cite the prompt-assembly code and
   confirm the secret or cross-tenant data is really in the context.
4. **Don't assert capabilities you can't see in source.** Claims depending on
   deployment facts not in the repo (is an "internal-only" endpoint actually
   unreachable, what a tool's target really exposes, which client renders
   output) are unverifiable from source — mark them so rather than reporting.
5. **Return only findings that pass gates 1–4** with the boundary crossed, the
   trusting code path, and the observable result.
