# Hunting: GraphQL injection

Load this companion only when the target actually uses GraphQL (`graphql`,
`apollo-server`, `graphql-yoga`, `@nestjs/graphql`, `graphene`, `strawberry-graphql`,
`gqlgen`, `async-graphql`, or a `.graphql`/`.graphqls` schema file present). If none of
these appear, skip this doc entirely — GraphQL injection cannot occur without a
GraphQL layer.

## Core discipline

GraphQL injection is narrowly about the **operation document** (the query/mutation/
subscription source string) being built from user-controlled input, not about anything
that happens inside a resolver once the document is fixed. A static document with
values bound only through the `variables`/`variableValues` map is the safe pattern —
`variables` never becomes the injection vector, only the document TEXT does.

## Classes

**graphql-document-injection**
- Sink/indicator: any point where a GraphQL operation document is assembled via
  string concatenation, interpolation, template literals with non-static
  expressions, or string formatting — `` `query { user(id: "${id}") { name } }` ``,
  `"query { " + fragment + " }"`, a JSON `query` field built by string concat for a
  downstream/forwarded GraphQL HTTP request, or a persisted-query system that selects
  document text by an unvalidated user-supplied key with no allowlist.
- Trace: does user-controlled input (request body/params/headers, or a stored value
  written earlier and read back later) reach the string that becomes the
  `source`/`document`/`query` argument to `execute()`/`graphql()`/a forwarded HTTP
  body, before that string is parsed? For persisted queries: is the document-ID → text
  mapping restricted to a server-side registry, or can the client influence which
  document text gets selected/assembled?
- FP trap: a static document string with only `variableValues`/`variables` populated
  from user input is NOT this class — that is the safe, intended pattern (still check
  resolver-level authorization separately, under `authz`). Resolver code that builds
  SQL/NoSQL queries from `args` on a fixed document is `sqli`/`deserialization`
  territory, never `graphql` — this class is document-injection only, never
  resolver-internal logic. Introspection being enabled is a hardening note, not this
  class, unless the actual finding is injection into the operation string itself.

## Validation rules

1. **Confirm the injected content changes document TEXT, not just a bound value.**
   Cite the exact concatenation/interpolation site and show the string that becomes
   the parsed document differs based on attacker input — a value flowing only into
   `variables` on an otherwise-fixed document does not qualify.
2. **Confirm the site is server-side document construction, not client-forwarding.**
   A server that merely parses and executes the client's own submitted document
   (`req.body.query` passed straight to `execute`) is not injection in itself — the
   client already controls their own document. Flag only where the SERVER builds a
   NEW document incorporating user strings before executing or forwarding it
   (e.g., a BFF/proxy that wraps or extends the client's query with server-added
   fragments built from request data).
3. **Check for an allowlist or persisted-query registry before reporting.** If
   document selection is restricted to a fixed, server-side set of allowed operations
   or IDs, the finding does not stand even if some string assembly is present upstream
   of that allowlist check.
4. **Return only findings that pass rules 1–3**, with the exact site, the tainted
   input's origin, and the resulting document-text change cited.
