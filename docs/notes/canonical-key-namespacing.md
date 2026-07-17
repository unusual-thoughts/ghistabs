# Task: namespace nested template-member types by their enclosing template

## Problem

Nested member types of a class template — `_Rep`, `_Alloc_hider`, `sentry`,
`pattern`, etc. — are keyed for canonicalization by their *bare simple name*. The
`<char>` and `<wchar_t>` instantiations of a template each define their own nested
`_Alloc_hider` (one holding `char*`, the other `wchar_t*`), but both land under one
canonical key `_Alloc_hider`. They are genuinely different types, so they diverge and
fork a `.conflict`; and the same collision means a per-category copy of a type can end
up carrying only some of its typedef aliases.

Two visible symptoms, same root:

1. **Residual `.conflict`s** after the layout-only ContentHash fix (`e441459`) are
   char-vs-wchar nested types sharing a bare key.
2. **`std::string` renders as `S` in xmltest's `tinyxml.cpp`** even after the
   readable-alias fix (`2aec6c4`): `basic_string<char>` exists as multiple DTM types
   across categories, and the `tinyxml.cpp` copy carries only the `S` typedef, not
   `string` — so the shortener has nothing better than `S` to fall back to.

## Evidence (xmltest_gcc421_fullstabs, post layout-only ContentHash fix)

`canonical-key-multi-hash` residual (after `e441459`) is dominated by:

```
/tinyxml.cpp/multi/_Alloc_hider            : 2 distinct bodies   # char* vs wchar_t*
/src/codecvt.cc/multi/…::_Rep              : 6 distinct bodies
…::sentry / pattern                        : 2–5 distinct bodies
basic_istream<char> / <wchar_t>            : forked per instantiation
```

`basic_string<char,…>::_Alloc_hider` (the fully-qualified name) is **unified** — one
body across all 36 CUs. It's only the **bare** `_Alloc_hider` key that collapses char
and wchar together. So the enclosing-template qualifier is what's missing from the key.

Decomp proof of the alias symptom: `EncodeString(S *str, S *outString)` in
`build/test-output/decomps/xmltest_gcc421_fullstabs/tinyxml.cpp` — that
`basic_string<char>` copy lives in the `tinyxml.cpp` category and only has the `S`
alias, while the libstdc++-category copy renders `string`.

## Root cause

Canonical keys for nested types use the simple leaf name (`_Alloc_hider`) rather than
the enclosing-scope-qualified name (`basic_string<char,…>::_Alloc_hider`). Note there
has already been related work — commit `cdb82ca` "namespace categories for all
method-bearing types" — but non-method-bearing nested member structs like
`_Alloc_hider` / `_Rep_base` / `sentry` / `pattern` are not covered.

## Solution

Qualify the canonical key (and DTM category) of a nested member type by its enclosing
template's name, so `basic_string<char>::_Alloc_hider` and
`basic_string<wchar_t>::_Alloc_hider` get distinct keys and never collide. Extend
whatever `cdb82ca` did for method-bearing types to *all* nested member types.

Design questions to resolve first:

1. **Where the enclosing scope is known.** Stabs nested-type names may or may not
   carry the `Outer::Inner` qualification depending on gcc version. Check the harvest:
   is `_Alloc_hider` emitted qualified (`basic_string<…>::_Alloc_hider`) or bare? If
   qualified, key on the full name; if bare, the enclosing scope must be recovered
   from the containing struct's field type-ref at materialization.
2. **Interaction with the readable-alias shortener** (`2aec6c4`): once each category
   copy is properly one canonical type, verify it carries the full alias set
   (`string`) so `S` disappears from `tinyxml.cpp` too.
3. **Interaction with the multi-category duplication.** The deeper question is whether
   `basic_string<char>` should be one DTM type instead of one per category — if
   unifying the outer type is in scope, the nested-key problem may resolve as a side
   effect. Decide: namespace-the-key (narrow) vs unify-across-categories (broad).

## Verification

1. Corpus `dtm-conflicts` / `canonical-key-multi-hash` before/after — the char/wchar
   nested-type entries (`_Alloc_hider`, `_Rep`, `sentry`, `pattern`) should collapse.
   Before-baseline in `scratchpad/BEFORE_CONFLICTS.txt` and `scratchpad/pre_S_fix/`.
2. Decomp: `EncodeString(string *str, …)` in xmltest's `tinyxml.cpp` (no more `S`),
   and `basic_istream<char,…>.conflict` gone.
3. Full corpus regression + xapasmcsr baseline (this touches canonicalization broadly).

## Files

- Canonical-key construction in the harvester / TypeRegistry (grep
  `canonical-key`, `canonicalKey`, `/multi/`). Start from what `cdb82ca` changed.
- `src/main/kotlin/ghistabs/materialize/TypeRegistry.kt` — category/key assignment.
- `src/main/kotlin/ghistabs/harvest/` — where nested member types get their names.

## Risk

Medium–high: changes canonicalization keys corpus-wide. Do it after the char-builtin
normalization (`char-builtin-normalization.md`), on its own commit, with the full
fixture set and baselines as the gate. Keep the "narrow (key) vs broad (unify)"
decision explicit in the commit message.
