# Pending work triage — integration failures, regressions, and log degradations

Written 2026-07-17 after the char-normalization + canonical-key-namespacing landings
(commits `8b60c92`, `9e2deb5`, `8c840ef`). Self-contained handoff: what's a real bug,
what's a spurious/expected test failure to silence, and a triage of every remaining
degradation/warning/error in the import logs.

Ground-truth fixture for most of this: `xmltest_gcc421_fullstabs` (libstdc++-heavy,
gcc 4.2.1 stabs). Its `after.log` is the reference. `scratchpad/pre_S_fix/` and
`scratchpad/BEFORE_CONFLICTS.txt` hold earlier baselines.

---

## UPDATE 2026-07-18 — foundational infra fixes + first honest full-corpus run

**Everything below in Parts 1–4 was triaged against a silently-degraded import.** Three foundational
bugs meant the suite ran effectively CONCURRENT-only and hid crashes as green skips:

1. **`TypeResolver` NPE (root cause).** The `init{}` pre-warm block was declared *above* the
   `astsByName`/`astsByBaseTag` `by lazy` delegates it reads (contentHash → byXRef → lookupByXRef).
   Kotlin assigns a `by lazy` delegate field only when construction reaches its declaration, so the
   init block read a **null Lazy delegate** → NPE on *every* import. Ghidra's analysis-task wrapper
   **swallowed** it in CONCURRENT (so CONCURRENT limped on with all xref resolution failing —
   degrading every CONCURRENT counter/result the triage relied on), and it was **fatal** in AFTER
   (`context.import()` in `setUp` threw → the whole AFTER invocation aborted). Fix: move `init` below
   the lazy declarations. *This is why "AFTER never ran" and why `-Pfixture` looked CONCURRENT-only.*
2. **`Dumps.kt registryDump` `.single()`** threw on fixtures with duplicate `(category,name)`
   DataTypes (libstdc++-heavy) → aborted AFTER `setUp` right after the import. Fix: `.first()`.
3. **`setUp` swallowed all exceptions into `assumeTrue(false)`** → real crashes read as skips. Fix:
   only a genuine binary-load failure skips; any import/analysis/dump crash fails loudly.

Infra added while here: `-Pmode=CONCURRENT|AFTER` filter, live per-fixture progress + ETA in the
gradle listener, `LiveTestReporter` (JUnit `TestWatcher` → `build/test-output/results/` with skip
reasons + setUp aborts), timestamped `results-history/` archiving. See [[reference_ghidra_stabs_test_running]].

**First honest full run (2h6m, all 21 fixtures × BOTH modes) — real failure landscape:**

| test | # cfgs | verdict |
|------|--------|---------|
| `demanglerHasNoEmptyStubs` | 15 (AFTER) | Whitelist expanded with **only 7 verified compiler-internals** (`__concurrence_lock_error`, `__concurrence_unlock_error`, `recursive_init_error`, `__array_type_info`, `__enum_type_info`, `__function_type_info`, `__fundamental_type_info` — never emitted with a body in any of the 21 harvests). **The earlier suggested additions were WRONG:** `__mt_alloc`, `__pool_alloc`, `__basic_file`, `_Deque_base`, `_Deque_iterator`, `_Vector_base`, `__normal_iterator`, `__pbase_type_info`, `__moneypunct_cache`, `__numpunct_cache` all carry **real stab bodies** in some fixtures → they're genuine §B/§E materialization gaps and must stay flagged. App templates (`tinyxml2::DynArray/MemPoolT`, `CryptoPP::AlgorithmImpl/BlockCipherFinal/…`) confirmed real §E gaps. |
| `mingwClassMethodsCarryThiscall` | 2 — `xmltest_gcc421_stripped`, both modes | **Item 1 (§Part 2) was a REAL bug, not a spurious skip.** This fixture builds class namespaces (so `classFuncs` is non-empty) but the methods never get `__thiscall`. The semantic `classFuncs.isNotEmpty()` gate correctly *surfaces* it — a `contains("stripped")` skip would have masked a real bug. Root cause still open. |
| `atLeastOneVtableStructApplied` | 8 | §C — structs built, not laid. |
| `fewSuffixedConflictRenames` | 8 | §B — multi-category duplication. |
| `voidSelfRefNotMaterialized` | 4 | §D — void self-ref leaks as Structure. |
| `countersWithinBaseline` | 7 (AFTER) | Baseline drift, **only** `xref-base-tag-resolved` (+1..+3 — the mode-sensitive counter `BaselineWriter` documents; the NPE fix restored the resolution). Baselines regenerated in place from the drift messages (no rerun). |

Net: Part 2 is settled (gates justified + whitelist precise + void twin gone). §A/§B/§C/§D/§E remain
open and are now measured honestly per-fixture. The `xmltest_gcc421_stripped` thiscall bug is new,
concrete work.

---

## Part 1 — the five "regressions" I originally flagged, retriaged

The earlier triage (during your in-progress changes) called five things regressions.
After instrumenting `collectAllVirtuals` (logged per-class `members`/`unionMethods`/
`unionVirt`/`result`), most changed status:

1. **Vtable virtual-detection ("no-virtuals" → 0 vftable structs) — NOT A BUG.**
   Instrumentation proved vftable structs *are* built: `exception` → `/std/exception`
   group, 3 virtuals; `ios_base` → `/std/ios_base`, 2 virtuals; `basic_streambuf` →
   `/std/streambuf` (typedef-shortened). The `vtable-skipped reason=no-virtuals` lines
   are a **separate method-less DUPLICATE group** per class (`/src/allocator-inst.cc/
   multi/basic_streambuf<char,…>`, `/libsupc++/del_op.cc/multi/exception`,
   `…/ios_base.h/ios_base`), harmless to vtables. `atLeastOneVtableStructApplied` passes.
   The 09:43 failure was transient mid-change. → see Part 3 "multi-category duplication"
   for the real underlying cause of the noise.

2. **Namespacing scope-collision / `sentry` — REAL, needs fixing.** See Part 3 §A.

3. **`voidSelfRefNotMateriali[sz]ed` (`_IO_marker`) — real bug + duplicate test.**
   See Part 2 (dedupe the twin test) and Part 3 §D.

4. **`fewSuffixedConflictRenames = 254 (>200)` — symptom of multi-category duplication,**
   not an independent threshold problem. See Part 3 §B.

5. **`countersWithinBaseline` (xapasmcsr) — not a bug, baseline refresh.** The drifted
   counters (`degraded-*-typed-all-undefined` → 0, etc.) are *improvements*. Refresh the
   baseline once §A settles (regenerate with `-PregenerateBaselines`, or hand-edit).

---

## Part 2 — reduce spurious / expected integration-test failures

These fail for reasons that are correct-by-design; make the assertions stop flagging them.
All in `src/test/kotlin/ghistabs/StabsImportRegressionTest.kt` unless noted.

- **`mingwClassMethodsCarryThiscall` on stripped fixtures.** `xmltest_gcc421_stripped`
  has no COFF symtab, so `setCallingConvention("__thiscall")` can't resolve → 32 methods
  untagged. Gate: `assumeTrue(!binaryName.contains("stripped"))`.

- **`demanglerHasNoEmptyStubs` — expand the whitelist.** The residual empty `/Demangler/*`
  stubs across the corpus are compiler-internal / forward-declared. Add to
  `ALLOWED_EMPTY_DEMANGLER_STUBS`: `__mt_alloc`, `__pool_alloc`, RTTI type-infos
  (`__array_type_info`, `__enum_type_info`, `__function_type_info`,
  `__fundamental_type_info`, `__pbase_type_info`), `__concurrence_lock_error`,
  `__concurrence_unlock_error`, `recursive_init_error`, `__basic_file<char>`,
  `_Deque_base`, `_Deque_iterator`, `_Vector_base`, plus the `<vector…>` `__normal_iterator`
  instantiations. **Keep flagged (real gaps):** `_Rb_tree_node`. **Do NOT whitelist the
  `sentry` / `__normal_iterator.conflict` stubs — they're §A's symptom; they should
  disappear when §A is fixed, and whitelisting would hide the regression.**
  App-template stubs (`tinyxml2::DynArray<…>`, `tinyxml2::MemPoolT<…>`,
  `CryptoPP::AlgorithmImpl<…>`, `BlockCipherFinal<…>`) are genuine materialization gaps —
  investigate separately, don't blanket-whitelist.

- **`voidSelfRefNotMateriali[sz]ed` twin test.** There are two copies of this test
  (`…Materialised` and `…Materialized`) — a leftover from the British→American spelling
  pass. Delete one.

- **`atLeastOneVtableStructApplied`** — passes now; no change needed. (The carve-out for
  `box2d_tests`/`xmltest` is still correct for genuinely C / no-C++-surface fixtures.)

---

## Part 3 — real remaining regressions / issues, and how to fix

### §A. Scope-collision demotion forks `istream`/`ostream`/`sentry` (the #2 bug)

**Symptom.** `after.log`: `canonical-scope-collision = 18` — `/std/istream`, `/std/ostream`,
`/std/iostream`, `/std/ostream/sentry`, `/std/istream/sentry`, … "divergent bodies →
demoted to header keys". Forks the nested `sentry` types → the empty
`std::{i,o,wi,wo}stream::sentry` demangler stubs.

**Root cause.** `TypeResolver.byCanonicalKey` (`TypeResolver.kt:358`) demotes a scope-keyed
group to header keys when its method-bearing owners don't all share one conten<<t hash:
`if (owners.groupBy { contentHash(it.body) }.size == 1)`. But the owners *do* have identical
layout — they diverge only in **methods**, because gcc emits a given virtual as
`VIRTUAL vtoff=0` in its defining CU and `NORMAL vtoff=null` elsewhere, and orders methods
differently per CU. `ContentHash` hashes methods (`ContentHash.kt:84`, order-sensitive,
flag-sensitive), so the owners' hashes differ → false "divergent" → demotion.

**Fix.** Make *only that owner-equivalence check* use a **layout-only** hash (drop methods).
Methods aren't part of the DTM struct, so their per-CU flag/order noise must not split the
group. Add a `layoutHash(body)` (Struct hash minus the `methods.map{…}` term) and use it at
`TypeResolver.kt:358` instead of `contentHash`. **Leave the global `contentHash` method-aware**
so the final merge (`TypeResolver.kt:369`, `slots.groupBy { contentHash(it.ast.body) }`) still
keeps the method-less header duplicate as a *separate* slot (don't merge it onto the
method-bearing winner — see §B).

Tried and rejected: sorting the per-method hashes (doesn't help — the flags differ, not just
order); unioning methods in `collectAllVirtuals` (inert — the divergent variants are in a
*different* group, not this one's `members`).

**Verify.** `canonical-scope-collision` → ~0 on xmltest; the `…stream::sentry` demangler
stubs resolve (drop out of `demanglerHasNoEmptyStubs`); the `NestedScopeKeyTest` cases stay
green. Full corpus regression + `harvest-collisions-divergent` must stay 0.

### §B. Multi-category duplication (underlies #1's noise and #4)

**Symptom.** Every libstdc++ class also materializes a spurious method-less duplicate group
under a `/src/…/multi/` or header category (e.g. `/src/allocator-inst.cc/multi/
basic_streambuf<char,…>`, `…/ios_base.h/ios_base`). These produce the harmless
`vtable-skipped no-virtuals` lines, feed `dtm-conflicts-created = 6`, and inflate
`_N`-suffixed conflict renames (`fewSuffixedConflictRenames = 254`).

**Root cause.** A class's method-less CU copies (no mangled method → `demangledClassPath()`
null → not scope-keyed) fall to header/`multi` keys instead of aliasing onto the class's
`/std/X` scope slot. The scope slot only absorbs method-less *nested* types
(`enclosingByNestedId`, `splitQualified`), not method-less copies of the *top-level* class
itself.

**Fix (design decision needed).** Either (narrow) recognize a method-less top-level copy
whose `ghidraName` equals a scope-keyed class and alias it onto that scope slot; or (broad)
give the scope slot's content the canonical category and drop the header duplicate. This is
the deferred work in `docs/notes/canonical-key-namespacing.md` — read that first. Fixing it
should clear the harmless no-virtuals skips, drop `dtm-conflicts-created` toward 0, and pull
`fewSuffixedConflictRenames` back under 200 (then re-check whether the threshold test is even
needed).

### §C. Vtable structs are built but never *laid* — needs real (non-hack) address resolution

**Symptom.** `vtable-failed-truly-missing = 121`, `vtable-applied = 0` on xmltest. The
`<Class>_vftable` structs are created (good — vfptr→type still resolves virtual calls), but
`resolveVtableAddress` (`ClassBuilder.kt:471`) can't locate `_ZTV<class>`, so nothing is laid
at the address point (no `offset_to_top`/RTTI header, no `vtable` symbol at the address point).

**Status.** Pre-existing, *not* a regression. Two of the three lookup paths are dead ends:

- `Itanium.ztvCandidates(className)` mangles-then-searches — but we have **no Itanium mangler**,
  only a demangler, so `mangleClassName` can't produce `St13basic_ostreamIcSt11char_traitsIcEE`
  from a class name. For `exception` it emitted `_ZTV9exception`, while the real symbol is
  `__ZTVSt9exception` (with the `St` = `std`). This path only works for global, non-template
  classes. **This is the hack; don't try to grow it.**
- `mangleClassName` on the leaf `className` is doubly wrong now that the scope lives in the
  category (`exception`, not `std::exception`).

**The non-hack fix: reverse-index the demangler, don't forward-mangle.** We *have* a demangler
and Ghidra imports the vtable symbols (verified: `__ZTVSt9exception` is an external `scl 2`
symbol at the same address as `.rdata$_ZTVSt9exception`). So:

1. Once per program, scan the symbol table; for each symbol where `looksLikeZtv`, demangle it,
   and if it's a `DemangledAddressTable` named `vtable`, record
   `qualified-class-name → address` in a map. O(symbols), built once — replaces the current
   per-class O(classes × symbols) scan in `resolveVtableAddress`.
2. Look each class up by its **qualified** name. Derive that from `demangledClassPath()` when the
   class is method-bearing, else **reconstruct it from the canonical key**: the scope is already
   in `key.category` (`/std` → `std`), so `std::` + leaf works for the method-less gcc-4.2.1
   libstdc++ classes too. (The uncommitted `qualifiedClassName` in `ClassBuilder.kt` only uses
   `demangledClassPath()` → leaf-fallback for method-less classes; extend it to the category
   reconstruction.)
3. `looksLikeZtv` must accept the form Ghidra actually exposes. The external `__ZTV…` is fine;
   the COFF section symbol `.rdata$_ZTV…` is rejected by `trimStart('_').startsWith("ZTV")`.
   Strip a leading `<section>$` before the check (or rely on the external symbol only).

**Open question to pin first (one instrumented run).** Even for method-bearing `exception`
(qualified name should be `std::exception`; `__ZTVSt9exception` is importable and
`looksLikeZtv`-passing), the current scan still misses. Log, in `resolveVtableAddress`:
`qualifiedClassName`, the count of `looksLikeZtv` symbols seen, and the first demangled chain
that *nearly* matches — to decide whether it's the symbol form (`.rdata$`), the AFTER-mode
symtab not carrying the symbol, or `qualifiedClassName` still resolving to the leaf.

**Ordering.** Fix §A first — the demoted `istream`/`ostream` groups lose their `/std` scope, so
their qualified name can't be reconstructed until they stop being demoted.

**Immediate, independent win:** emit a `vtable-struct-only` degradation when `collectAllVirtuals`
is non-empty but `resolveVtableAddress` returns null, so "built but not laid" is visible and not
conflated with "no vtable at all" — even before the real resolution lands.

### §D. `_IO_marker` void self-ref leaks as a Structure

**Symptom.** `voidSelfRefNotMateriali[sz]ed`: "void self-Refs leaked as Structures:
[/libio.h/_IO_marker] (out of 14 void asts)". A glibc/newlib struct with a self-referential
`next` pointer resolves to a `Structure` instead of void.

**Status.** Real gap; needs a full-suite run to confirm it's still present after your rerun.
Investigate the void self-ref detection for the pointer-to-self case (`_IO_marker` has
`struct _IO_marker *_next`), likely in the void-detection path referenced by
`[[project_stabs_void_selfref]]`.

### §E. App-template demangler stubs (genuine materialization gaps)

`tinyxml2::DynArray<…>`, `tinyxml2::MemPoolT<…>`, `CryptoPP::AlgorithmImpl<…>`,
`BlockCipherFinal<…>` — the binary's *own* instantiated templates left as empty
`/Demangler/*` stubs. If the CU defines them fully, these are real misses (not
compiler-internal), worth chasing after §A/§B. Do not whitelist.

### §F. Stop flagging RTTI typeinfo globals as degradations (`degraded-*-typed-xref-stub`)

**Symptom.** `degraded-global-typed-xref-stub` is the single largest degradation counter
corpus-wide (up to **1322** on `crypto_mi_test_gcc345`, ~1320 on `xapasmcsr`). It's mostly a
**false alarm**: the entries are `_ZTI*` RTTI typeinfo globals correctly typed as their RTTI
structure — `_ZTISt9exception :: /ClassDataTypes/ClassTypeInfoStructure`,
`_ZTIN8CryptoPP9ExceptionE :: SiClassTypeInfoStructure`. The output is *right*; it's the
degradation *reporting* that's wrong.

**Fix.** In the degradation-emitting path (where `degraded-<scope>-typed-xref-stub` is raised —
`SymbolApplier` / `TypeDiagnostics`), suppress it when the applied type is one of the RTTI
structures (`ClassTypeInfoStructure` / `SiClassTypeInfoStructure` / `VmiClassTypeInfoStructure*`)
or when the symbol name is a `_ZTI*` typeinfo. These are handled by `rtti-pseudo-substituted`
and are correct-by-construction, not a materialization gap. Leaving them makes the counter
useless — the *non-`_ZTI`* xref-stub globals (real forward-decl gaps) are drowned out. After
this, the counter should reflect only genuine gaps.

---

## Part 4 — triage of remaining degradations / warnings / errors

Counts are `xmltest_gcc421_fullstabs` unless noted; the `-typed-*` family and RTTI counts are
corpus-wide (biggest on `crypto_mi_test_gcc345` / `xapasmcsr`). Grouped by verdict.

### 4a — real, needs fixing (tracked in Parts 2/3)

| counter                                                  | count       | verdict                                                                                                                                                                                                                                                           |
|----------------------------------------------------------|-------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `apply-error` / `apply-error-duplicate-name`             | 8           | Placement `operator new`/`operator delete` (`_ZnwjPv`, `_ZdlPvS_`) — COMDAT-folded to one address across CUs; `setName` collides with the pre-existing PE label. Guard `setName` on an existing same-name symbol at the addr, or dedupe openFunctions by address. |
| `apply-error-invalid-input`                              | 24 (crypto) | `[ERROR]`. CryptoPP heavily-templated functions (`_ZN8CryptoPP14MakeParameters…`) — signature application throws "invalid input". Investigate the param/return construction for deeply-nested template signatures.                                                |
| `apply-error-parameter-mismatch`                         | 5 (crypto)  | `[ERROR]`. "Parameter name conflicts with…" on template `operator+` (`_ZStplIc…`). Likely a duplicate param name after our reparent; dedupe param names.                                                                                                          |
| `canonical-scope-collision`                              | 18          | §A — layout-only owner hash.                                                                                                                                                                                                                                      |
| `xref-ambiguous` / `xref-base-tag-ambiguous`             | 51          | An XRef resolves to several same-name candidates. Notable count; tied to the multi-category duplication (§B) and canonicalization — should fall as §A/§B land. Audit residual after.                                                                              |
| `global-applied-then-overwritten`                        | 5 (crypto)  | A global's type was written but readback is null (`_ZN8CryptoPP10g_hasSSSE3E: wrote bool but readback is null`) — the DataUtilities write didn't stick (clash with existing data/auto-analysis). Investigate.                                                     |
| `class-not-struct`                                       | 4           | A class canonicalized to a `Union` (e.g. `_Obj` in `__default_alloc_template`) so class-building skips it. Edge case; the alloc-template union member.                                                                                                            |
| `vfptr-collision`                                        | 1           | `CLexStream: cannot place {vfptr} at +0 (occupied by <anon>)`. Residual of the static-member/anon-field-at-0 issue; down from 2. One case left to chase.                                                                                                          |
| `canonical-key-multi-hash`                               | 31          | Residual char/wchar + multi-category (§B) + a few system structs. Falls with §A/§B.                                                                                                                                                                               |
| `dtm-conflicts-created` / `-post`                        | 6           | §B multi-category `.conflict` forks. Falls with §B.                                                                                                                                                                                                               |
| `degraded-vtable-failed` / `vtable-failed-truly-missing` | 121         | §C — structs built, not laid. Real (eventual) fix via demangler reverse-index; flag "built-not-laid" now.                                                                                                                                                         |
| `demangler-skip-no-replacement`                          | 23          | The residual empty `/Demangler/*` stubs — Part 2 whitelist (compiler-internal) + §E (app templates) + §A (`sentry`). Split accordingly.                                                                                                                           |
| `degraded-field-dropped`                                 | 1           | Down from 463 pre static-member fix; the residual 1 is worth a look.                                                                                                                                                                                              |
| `degraded-base-layout-failed`                            | 1           | One base couldn't be laid; inspect the class.                                                                                                                                                                                                                     |
| `inheritance-failed`                                     | 1           | One inheritance edge failed to apply; inspect.                                                                                                                                                                                                                    |

### 4b — the `degraded-*-typed-*` family (globals/statics/locals whose type degraded)

**Twelve** counters: `{global,static,local,param}` × `{xref-stub, anonymous, all-undefined}`
(I originally listed only global/static/local — the **`param` variants exist too**). Plus the
`-untyped` pair below. Corpus-wide.

| counter                                              | count (xmltest / max-corpus)  | verdict                                                                                                                                                                                                                                         |
|------------------------------------------------------|-------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `degraded-{global,local,static}-typed-xref-stub`     | 0 / **1322** (gcc345, crypto) | **§F — mostly RTTI false alarm; stop emitting.** `_ZTI*` typeinfo globals correctly typed as their RTTI structure. Only the *non-`_ZTI`* remainder is a real forward-decl gap.                                                                  |
| `degraded-param-typed-all-undefined` / `-anonymous`  | 26 (crypto)                   | **Missed originally.** Params typed all-Undefined / anon — CryptoPP `Singleton<…>` deep template params. Expected-ish; audit for real gaps.                                                                                                     |
| `degraded-{global,local,static}-typed-anonymous`     | small                         | Typed with an anonymous (`$_N`) aggregate. Expected; low.                                                                                                                                                                                       |
| `degraded-{global,local,static}-typed-all-undefined` | 40 / 4 / 1                    | Type resolved to all-`UndefinedN`. **Newly truthful:** `8c840ef` fixed the `Undefined.isUndefined` vs `is Undefined` bug that had *zeroed* these. Mostly libstdc++ locals with unresolved template types. Not new degradations; audit a sample. |
| `degraded-local-untyped` / `degraded-param-untyped`  | 56 (crypto)                   | **Missed originally.** Local/param with no type at all (optimized-out slots, tinyxml `XMLUtil` digits). Expected.                                                                                                                               |

### 4c — expected / structural (libstdc++ RTTI-only surface), low priority
 
| counter                                              | count    | verdict                                                                                                                  |
|------------------------------------------------------|----------|--------------------------------------------------------------------------------------------------------------------------|
| `degraded-struct-truncated`                          | 40       | Facets trimmed to last-described byte (forward-decl-only CUs). Cross-check the static-member `,0,0` handling.            |
| `degraded-struct-mostly-undefined`                   | 36       | Facet structs mostly `Undefined1` (forward-decl). Expected.                                                              |
| `degraded-base-synthesized`                          | 10       | EBO/base-subobject placeholders synthesized. Expected.                                                                   |
| `base-empty-ebo`                                     | 42       | Empty-base-optimization bases recognized. Informational (not a degradation).                                             |
| `canonical-key-multi-kind`                           | 4        | Anon `$_N` resolving to both Enum and Struct. Low; anon-kind ambiguity.                                                  |
| `method-implicit-not-emitted`                        | 126      | gcc-implicit trivial special members with no emitted symbol. Expected.                                                   |
| `unresolved-symbol`                                  | 987      | Externs, implicit special members, DLL imports. Not actionable in bulk.                                                  |
| `unresolved-xref` / `xref-undefined`                 | 12 / 12  | Forward XRefs never resolved. Low.                                                                                       |
| `local-var-skipped-dup-local` / `-dup-param`         | 93 / 343 | Duplicate PSYM/LSYM locals skipped. Expected (gcc emits dups).                                                           |
| `desc-dropped-so` / `-undf`                          | 123 / 1  | N_SO / undef descriptors dropped. Expected (boundary records).                                                           |
| `drop-record-bnsym` / `-ensym`                       | 2806     | BN_SYM/EN_SYM boundary records — gcc-4.2.1 emits these; expected.                                                        |
| `drop-record-opt` / `-undf-empty`                    | 64 / 15  | Optimized-out / empty-undef records dropped. Expected.                                                                   |
| `data-no-coverage`                                   | 172      | Data bytes with no type coverage. Informational (coverage pass).                                                         |
| `text-undisassembled-code` / `text-data-no-coverage` | 305 / 3  | Disassembly-coverage counters (FillerByteAnalyzer / HullDisassembly). Informational; xapasmcsr baselines these (see #5). |

### 4d — positive / context (not degradations; here so they're not mistaken for problems)

`canonical-key-merged = 457` (successful cross-CU merges), `replaced-demangler = 169`,
`rtti-pseudo-substituted = 5` (RTTI structs substituted — pairs with the xref-stub typeinfo),
`vfptr-inherited-from-base = 113` / `vfptr-normalized = 15` (vfptr placement),
`xref-base-tag-resolved = 56`, `typedef-named-anon-aggregate = 3`,
`inheritance-applied = 233`, `harvest-collisions-divergent = 0` (the invariant to keep at 0).

**Cleanup priority from the log:** (1) the 8 `[ERROR]` `apply-error` (only errors, easy guard);
(2) §A scope-collision (drops multi-hash + sentry stubs); (3) §B multi-category (drops
conflicts + `_N` renames + no-virtuals noise); (4) re-bucket RTTI-typeinfo out of
`degraded-*-typed-xref-stub` so that counter reflects only real forward-decl gaps.

---

## Suggested order

1. **Part 2** spurious-test cleanup (cheap, unblocks CI signal): stripped-fixture gate,
   whitelist additions, dedupe the void-self-ref twin.
2. **§A** scope-collision layout-only hash (self-contained, clears sentry stubs + multi-hash).
3. **§B** multi-category duplication (bigger; read `canonical-key-namespacing.md`) — clears
   `#1` noise, `#4`, and most conflicts.
4. **§C** flag "built-not-laid" + revisit `looksLikeZtv`/qualified-name for real address
   resolution.
5. **§D** `_IO_marker`; **§E** app-template stubs.
6. **#5** xapasmcsr baseline refresh, last, once counts settle.
