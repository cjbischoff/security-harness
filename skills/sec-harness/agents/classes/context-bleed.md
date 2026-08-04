# CWE-class extension — context-bleed

Thin extension imported by investigate/patch on top of the shared preamble. Adds ONLY
the class-specific bits; the gate ladder + tool-receipt rules come from the base prompt.

## Canonical fix shape
Scope the conversation-history/embedding/KV-prompt-cache key per user/tenant. Apply a
per-tenant metadata/ACL filter at query time for every retrieval path, not just a tenant
field on the stored document.

## Discrimination requirement
Documents tagged with a tenant field but never filtered on is the bug; a tenant field
that IS applied in the query's `WHERE`/filter clause is not — cite the query, not the
schema.

## Class boundary
**IS:** an AI-system-specific shared-state mechanism (conversation history, embedding
store, KV/prompt cache) that mixes data across principals because the cache/query key
isn't scoped per user or tenant.
**IS NOT:**
- A conventional multi-tenant DB query missing a `tenant_id`/`WHERE` scope with no
  AI/embedding/cache component involved → `cls: authz` (plain BOLA), not context-bleed.
  Use context-bleed specifically when the shared surface is a model-serving artifact
  (prompt cache, vector index, agent memory).

## Proof tuple (required evidence)

A confirmable context-bleed needs all three, each with a `file:line`:
1. **Shared context/memory across principals** — a cache/session/embedding key construction that is not scoped per user or tenant.
2. **A read path returning another principal's data** — the retrieval query lacks a per-tenant ACL/metadata filter at query time.
3. **Attacker-reachable trigger** — a request an attacker controls can cause the mixed-tenant read to occur.

**Instance preservation:** do NOT collapse sibling instances that share a CWE but hit distinct concrete sinks/routes into one finding. Expand every concrete instance as its own candidate; dedupe merges only exact `(file,line,cls)` collisions.
