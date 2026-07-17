# Task: normalize char builtin spellings in ContentHash

## Problem

The same primitive type — `char` — is emitted by gcc in two different stab forms
depending on the CU, and `ContentHash` treats them as distinct. Any struct that
transitively contains a bare `char` member therefore hashes two different ways
across CUs, forks a `.conflict` in the DTM, and shows up as `Foo.conflict` in the
decompiler.

## Evidence (xmltest_gcc421_fullstabs)

The same `basic_string<char>::_Alloc_hider` element type `_M_p` (a `char*`) is spelled:

- **40 CUs**: `Ptr(Range(0,127))`  — char as a bounded range
- **36 CUs**: `Ptr(WithSizeAttr(8, …))` — char as a size-attribute wrapper

(A third `Ptr(Range(0,65535))` group is genuinely `wchar_t*`, not a bug.)

Raw stabs for the char family on this target:

```
char:t(0,2)=r(0,2);0;127;          # plain char, range 0..127
signed char:t(0,14)=r(0,14);-128;127;
unsigned char:t(0,11)=r(0,11);0;255;
```

After the layout-only ContentHash fix (commit `e441459`) the cycle-driven
divergence collapsed (`basic_string<char>` 11 hashes → 1), but the residual
`dtm-conflicts` on xmltest are all `basic_istream<char>` / `basic_ostream<char>` /
`basic_ios<char>` — types that carry a bare `char` member (char_type/traits), where
the `Range` vs `WithSizeAttr` spelling still splits them 2 ways.

`BuiltinTable` already resolves *both* forms to Ghidra's `CharDataType` at
materialization time (commit `237a693`), so the two spellings are known-equivalent —
`ContentHash` just doesn't know it.

## Root cause

`ContentHash` (`src/main/kotlin/ghistabs/harvest/ContentHash.kt`) hashes:

- `Range` → `Objects.hash("Range", of.refKey(...), min, max)`
- `WithSizeAttr` → `Objects.hash("WithSizeAttr", sizeBits, inner.contentHash(...))`

These produce different hashes for the same char. There is no builtin-normalization
step, so `Range(0,127)` and `WithSizeAttr(8, Range/Builtin)` never converge.

## Solution

Normalize builtin primitives to a single canonical hash keyed by *what Ghidra type
they materialize to*, mirroring `BuiltinTable.resolve`. Concretely: before hashing a
`Range` / `WithSizeAttr` / `Builtin` node, run it through the same classification
`BuiltinTable` uses (or a shared helper) and hash the resulting Ghidra-type identity
(e.g. the datatype's name/size) instead of the raw stab shape. Then:

- `Range(0,127)` → `char`
- `WithSizeAttr(8, <char>)` → `char`
- both hash identically.

Keep it narrow — only collapse forms `BuiltinTable` already maps to the *same*
Ghidra primitive; don't merge distinct primitives. `signed char` (-128..127) and
`unsigned char` (0..255) must stay distinct from plain `char` (0..127) exactly as
`BuiltinTable` distinguishes them.

Candidate implementation: factor the range/size-attr → Ghidra-primitive decision in
`BuiltinTable` into a pure classifier returning a stable key, and call it from both
`BuiltinTable.resolve` (materialization) and `ContentHash` (the `Range`,
`WithSizeAttr`, and `Builtin` cases). One source of truth for "these stab shapes are
the same primitive."

## Verification

1. Unit: add `ContentHashTest` cases asserting `Range(0,127)`,
   `WithSizeAttr(8, Range(0,127))`, and `Builtin(-2)` (char slot) all hash equal, and
   that `Range(0,255)` / `Range(-128,127)` stay distinct.
2. Corpus: before/after `dtm-conflicts` and `canonical-key-multi-hash` on
   `xmltest_gcc421_fullstabs`. Expect the `basic_istream`/`basic_ostream`/`basic_ios`
   `<char>` `.conflict` entries to collapse. Before-baseline captured in
   `scratchpad/BEFORE_CONFLICTS.txt` (dtm-conflicts xmltest 10→6 after the layout-only
   fix; this task should push it further down).
3. Decomp eyeball: `basic_istream<char,…>.conflict` should disappear from
   `build/test-output/decomps/xmltest_gcc421_fullstabs/`.

## Files

- `src/main/kotlin/ghistabs/harvest/ContentHash.kt` — `Range` / `WithSizeAttr` /
  `Builtin` cases (lines ~45, ~101, ~103).
- `src/main/kotlin/ghistabs/materialize/BuiltinTable.kt` — the classifier to share
  (range branch ~line 44, slot table ~line 81).
- `src/test/kotlin/ghistabs/harvest/ContentHashTest.kt` — new cases.

## Risk

Low–medium: `ContentHash` drives all cross-CU dedup, so run the full corpus and watch
`harvest-collisions-divergent` (must stay 0) and the xapasmcsr baseline. Do it on its
own commit with the conflict counts as the regression gate.
