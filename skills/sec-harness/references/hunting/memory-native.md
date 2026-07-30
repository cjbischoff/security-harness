# Hunting: memory safety & native code

**Out of scope unless the target contains native/unsafe code.** This companion
applies only when recon confirms C/C++/Objective-C, Rust `unsafe`, a kernel
module/driver, or a parser/decoder written in one of those. This harness is
static-only, no-exec — do not load this file for pure managed-language
(Python/JS/Java/Go-without-cgo) targets; the classes below don't apply and
pulling them in wastes agent budget on unreachable surface. If recon finds any
`unsafe`/`cgo`/JNI boundary inside an otherwise managed codebase, scope this
file to ONLY that boundary code, not the whole repo.

## Core discipline

- A buffer sized for the common case can still overflow on adversarial input.
  Verify every "this length is bounded" claim against the WORST case the type
  allows, not the happy path the tests exercise.
- "Huge count = guaranteed crash" is false. An oversized copy length is size-
  and libc-dependent — it often faults, but can also wrap or produce a short,
  scattered write first. Determine the actual write behavior before downgrading
  a finding to DoS-only.
- Static offsets are a guess; a reproduced crash is truth. An unreproduced
  memory-safety claim is not a finding — this harness cannot execute the
  target, so anything requiring dynamic reproduction is unverifiable from
  source and must be marked as such, not asserted.
- Sanitizer coverage is not a substitute for reading the code — a clean-looking
  path outside instrumented code (hand-written asm, JIT-emitted, an
  intra-allocation deref) gets no credit from "sanitizers would catch this."

## Classes

**spatial-oob** (out-of-bounds read/write)
- Sink/indicator: any pointer-arithmetic copy/loop bound derived from
  subtraction, an unparenthesized multi-term length expression, or a
  `sizeof(*p)`-style size computation.
- Trace: for subtraction bounds (`a - b`), can the attacker make `b > a`,
  underflowing to a huge unsigned value? For multi-term chains
  (`endp - begin + consume`), does one term come from attacker-sized input,
  silently over-adding? For `sizeof` size computations, does the pointer depth
  match the actual element type, or is the allocation/copy sized one
  indirection off? For a wire-length copied into a fixed buffer, is the true
  headroom (buffer size minus any fixed prefix already written) computed before
  the copy, or assumed?
- FP trap: a bound expression that LOOKS unchecked but is actually validated by
  a caller earlier in the call chain is not a finding — exhaust callers (not
  the first one) before concluding the check is missing.

**temporal-uaf** (use-after-free / lifetime)
- Sink/indicator: a free/release path and every wakeup/callback/view path that
  can still reach the same object afterward.
- Trace: for an embedded waiter/anchor structure, does EVERY free path drain
  the wakeup list, or only the primary one? For a cached raw pointer into a
  reallocatable buffer, does the invalidation logic walk the actual current
  view set, or does grow/realloc replace the wrapper the invalidation walks?
- FP trap: without a reproduced crash or a reclaim-and-compare demonstration
  (trigger the dangling reference, reclaim the freed region with a
  size-matched allocation, write through the dangler, read back through the
  reclaimer), this is a lead, not a confirmed finding — mark it unverifiable
  from source if you cannot execute the target.

**type-confusion**
- Sink/indicator: a tagged-union/cast operation (`OSDynamicCast`-style,
  NaN-boxing, a cached typed-array data pointer) and any hierarchical walker
  (page-table/nested/B-tree) that checks a valid bit without checking a
  leaf/size bit.
- Trace: does the cast/read path check the actual type tag before treating the
  value as a pointer (read confusion) or before writing a scalar into a pointer
  slot (write confusion)? Does a walker that checks "is this entry valid" also
  check "is this entry a leaf" before descending into it as an interior node?
- FP trap: a cast result that IS null-checked, or a walker that DOES check the
  leaf/size bit at every level, is not this bug — cite the specific level or
  call site where the check is skipped, not the general pattern's presence
  elsewhere in the same file.

## Validation rules

1. **Confirm native/unsafe code is actually in scope** before spawning this
   class at all — a managed-language codebase with no `unsafe`/cgo/JNI boundary
   gets none of these classes investigated.
2. **Read the offset from a reproduced crash, not disassembly alone.** A
   variable-length prefix (handle, optional field, padding) shifts geometry off
   a static prediction — do not assert an exact offset you haven't reproduced.
3. **Distinguish crash from exploitable.** For an OOB write, state which bytes
   land where and whether a security-relevant field is reachable; for a "huge
   count" claim, establish the bounded-write case exists before calling it
   DoS-only.
4. **Reproduction gate.** Since this harness is static-only and cannot execute
   the target, any claim that depends on dynamic behavior (actual crash
   location, actual write pattern, actual heap layout) is unverifiable from
   source — report it as a lead requiring deployment/dynamic testing, never as
   a confirmed finding with an asserted severity.
5. **Return only findings that pass gates 1–4** with the exact input path to
   the unsafe operation and the observable static evidence — everything
   requiring execution to confirm goes in the lead/unverifiable bucket.
