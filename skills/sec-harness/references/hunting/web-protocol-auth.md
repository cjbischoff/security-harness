# Hunting: web protocol & auth

Load this companion when recon flags a reverse proxy/CDN/gateway, a custom HTTP
parser, or an auth protocol (sessions, JWT, OAuth/OIDC, SAML, password reset).
`attack-classes.md`'s `authz`/`authn` rows cover "is a check present"; this file
covers "can the attacker forge, replay, or desync the identity/request the check
runs on." Use both.

## Core discipline

- Framing bugs are a DISAGREEMENT between two components, never a defect in one
  parser read in isolation. Name both components and the byte they parse
  differently before calling it smuggling or cache poisoning.
- A signature nobody verifies is decoration. For every token type, cite the exact
  line that calls verify AND the claims it checks (`exp`/`aud`/`iss`/`nonce` for
  JWT/OIDC). Decoding without verifying is not verification.
- Every read of `Host`, `X-Forwarded-*`, `Forwarded`, or any request-derived URL
  is a trust decision — trace it to what it controls (reset link, cache key,
  redirect, access check).
- Client vs. server role gates everything: `redirect_uri` allowlisting, PKCE
  enforcement, and assertion signing are the IdP/authorization-server's job, not
  the relying-party client's. Establish which role the code plays before citing
  a missing control.
- Reflected request input landing in a security-relevant response field
  (`Set-Cookie`, `Location`, a cache key, an absolute URL sent to a victim) needs
  a traced cross-user impact, even when it isn't classic XSS.

## Classes

**jwt** (alg/kid/jku confusion — CWE-347/345)
- Sink/indicator: the JWT verify/decode call (`jwt.verify`, `jwt.decode` with
  `verify=False`, `jose.jwt.decode`) and the header fields `alg`/`kid`/`jku`/`x5u`.
- Trace: find where `alg` is chosen — read from the untrusted token header, or
  pinned server-side to an allowlist? Then find where `kid` selects a key: used
  in a file path (traversal) or a DB lookup (injection)? Then find where `jku`/
  `x5u` fetches a key set — from an attacker-writable URL? Then confirm claim
  checks (`exp`, `aud`, `iss`) exist alongside the signature check.
- FP trap: modern JWT libraries default to rejecting `alg: none` and require an
  explicit algorithm allowlist at the call site. Read the library version and the
  actual call signature before reporting `alg` confusion — a library-enforced
  allowlist closes this even if the app never mentions `alg` explicitly.

**oauth-oidc** (state/PKCE/nonce/redirect_uri)
- Sink/indicator: the authorization-code exchange endpoint, the callback handler
  reading `code`/`state`, and PKCE `code_verifier`/`code_challenge` comparison.
- Trace: is `redirect_uri` validated by exact match (not substring/prefix) and
  bound to the client? Is `state` generated, session-bound, and checked on
  return? Is PKCE enforced for public clients, and is `code_verifier` actually
  compared, not just present? Does `id_token` validation check `aud`, `iss`,
  signature, AND `nonce`?
- FP trap: `state` is a CSRF/session-binding control, not the anti-replay control
  for authorization codes — that's PKCE and OIDC `nonce`. Don't report "missing
  `state`" as if it prevents code injection, and don't fault a relying-party
  client for skipping `redirect_uri` allowlisting — that's the authorization
  server's control.

**saml** (signature wrapping / exclusion — CWE-347)
- Sink/indicator: the assertion signature-verification call and the identity
  extraction call (`NameID` read) in the SAML consumer.
- Trace: find what the verifier signature-checks (which XML element) versus what
  the identity-extraction code reads (which element) — XSW exists in the gap
  between them. Check whether unsigned assertions are accepted, or verification
  is skippable via a flag. Check `NotBefore`/`NotOnOrAfter`, `Recipient`/
  `Audience`, `InResponseTo`, and one-time-use/replay rejection separately from
  the signature check — a valid signature does not imply the assertion wasn't
  stolen and replayed.
- FP trap: a signature-wrapping-shaped bug requires actually showing the checked
  element and the read element diverge — "the app uses SAML" or "XML canon-
  icalization exists" is not evidence; cite the two call sites.

**request-smuggling** (CWE-444)
- Sink/indicator: any component that parses/forwards HTTP itself — a custom
  proxy, a framework's own HTTP server, header normalization middleware.
- Trace: find every place `Content-Length` and `Transfer-Encoding` are read; walk
  the HTTP/2-front-to-HTTP/1.1-back hop for downgrade smuggling (H2.CL/H2.TE);
  check whether duplicate/obfuscated/whitespace-padded `Transfer-Encoding` and
  CRLF-in-header-value survive the forwarding hop. Feed the same ambiguous bytes
  to both parsers on paper — divergence is the bug.
- FP trap: a single server with no proxy/gateway in front has no smuggling
  surface at all. Confirming only the in-repo half (this parser mishandles a
  specific ambiguous input) is a lead, not a finding — it needs the paired
  front-end to actually be desynced from it.

**cache-poisoning** (CWE-444)
- Sink/indicator: the cache-key construction function and every input that
  changes the response but isn't in that key.
- Trace: enumerate response-varying inputs (`X-Forwarded-Host`, custom headers,
  cookies, query params normalized out of the key) not covered by the cache key;
  confirm the unkeyed input reaches the cached response body or headers (not
  just an internal log).
- FP trap: an unkeyed input that changes the response but is never actually
  cached (a `no-store`/`private` directive, a cache rule that excludes the
  route) is not exploitable — verify the response is actually stored and served
  to a second party, not just that the key is incomplete on paper.

## Validation rules

1. **Source-visibility gate.** Framing bugs, cache-key config, secret strength,
   and token entropy often depend on a proxy chain or config not in the audited
   tree. If confirming requires a component/config/secret you cannot read, this
   is unverifiable from source — do not report it as a confirmed finding.
   1a. If you confirmed only the in-repo half (this parser genuinely mishandles
       a specific ambiguous input), record it as a lead with the exact bytes,
       not a severity-rated finding.
2. **Token findings must cite the verify line and the missing check.** Point at
   the `verify`/`decode` call and name the specific claim/algorithm/key-selection
   step it skips.
   2a. Establish client-vs-server role before faulting a control — a
       relying-party client does not own `redirect_uri` allowlisting or
       assertion signing.
3. **Cross-user impact is mandatory.** Show the payload reaching a victim's
   response (cache), request (smuggling), session (fixation), or inbox (reset
   link) — an attacker-only effect is a hardening note, not a finding.
4. **Check the framework/library default before reporting.** Many stacks strip
   CR/LF, rotate sessions on login, key caches on `Host`, and JWT libraries
   increasingly enforce an algorithm allowlist by default. If you cannot
   determine the library's default, treat the claim as unverifiable rather than
   assuming vulnerable.
5. **Return only findings that pass gates 1–4.** Everything else is a lead
   ("requires deployment testing") or a hardening note — say so explicitly.
