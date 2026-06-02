## not triaged

- [ ] make sure there are no trivial tests that don't test anything real
- [ ] simplify or explain the hairy parts of the algorithms (cu deduplication, placeholders, attribution, multiple
  passes, registries, hashes, etc) in a README
- [ ] identify any code duplication, vestigial stuff etc
- [ ] avoid files with just one trivial class
- [ ] remove references to "phases", specific binaries/programs or classes/types from code documentation
- [ ] add missing code docs (Harvester for example)

## Done

- [x] replace garbage Baseline parsing with actual kotlinx.serialization
- [x] diagnostics: dump entire ast database (possibly with a DSL) — `Harvest.kt`
  serializes typeAsts/symbolsByCu/openFunctions; written to
  `src/test/resources/harvests/xapasmcsr-harvest.json` from
  `StabsAnalyzerRegressionTest.setUp`. Companion log at
  `src/test/resources/logs/xapasmcsr.log`.
- [x] _vptr$Inst (first field of Inst) has type `__Normal` — was a cross-CU
  TypeId collision (every CU's source file got fileNum=1; (1,n) collided
  across CUs). Fixed in `4b21a6c` by namespacing local source ids under the
  cuFile in `IncludeContext.canonicalTypeId`. Harvest now shows
  `_vptr$Inst: InlineDef → Pointer → Ref(23,22)` (the real vtable pointer).
- [x] still no vtable types at all — `[vtable] applied` fires 18× on
  xapasmcsr.exe. Covered by `atLeastOneVtableStructApplied` and
  `mostPolymorphicClassesHaveVtableStruct`.
- [x] still no inheritance working (eg ExprInst) — `inheritance-applied`
  counter = 170. XapInst → ExprInst → Inst hierarchy resolves correctly.
  DCInst → ExprInst (encoded as `InlineDef(id, XRef body)`) fixed in `ffaa808`
  by extending `resolveBaseAstStatic` to follow the InlineDef id first.
  Covered by `xapInstFirstComponentIsBase`, `cLexStreamHasBaseField`,
  `inheritanceWasApplied`.
- [x] missing argument names for every fun — ordering issue: importer must
  run after auto-analysis. Confirmed; harness orders it correctly.
- [x] "Function body must contain the entrypoint" — same ordering issue.
- [x] xapasmcsr needs to use mingw compiler pspec — `778ea50`.
- [x] **globals still not typed** — `ProgramAddressResolver.resolve` now tries
  the `_<name>` (PE/Cygwin one-extra-underscore) variant unconditionally. Hits
  both C globals (`BranchInstructions` → `_BranchInstructions`) and Itanium
  C++ RTTI (`_ZTI<class>` → `__ZTI<class>`). `global-applied` went 14 → 50,
  `unresolved-symbol` 1234 → 1116.
- [x] **full stabs parser? any tokens ignored?** — `Harvest.passA` now
  enumerates every `StabType` value explicitly: handled types do work,
  known-irrelevant types (line numbers, compiler options, Apple/Sun
  cross-toolchain codes) increment silent counters via `BookmarkSink.bump`,
  and `StabType.UNKNOWN` logs loudly with the raw byte. Added missing codes
  from `binutils/include/aout/stab.def` (N_ROSYM, N_BNSYM, N_ENSYM, N_OBJ,
  N_ALIAS, N_NSYMS, N_NOMAP, N_PATCH, N_WITH, N_NBTEXT…, N_MAC_DEFINE,
  N_MAC_UNDEF). Zero UNKNOWN on xapasmcsr.exe.
- [x] **logging / diag — log spam reduction** — three sources fixed:
  - per-N_SLINE `[drop-record]` (23 901× → 0; silent counter).
  - per-4-byte `[stabs-no-coverage]` (4820× → 89; contiguous gaps
    coalesced into one log entry per range in `analyzeBssCoverage`).
  - log file dropped from ~32 k lines to ~3 k.
- [ ] **duplicated `this` parameters** — needs reproduction. Likely the
  signature-application pass adds `this` even when the parser already
  emitted one from the stabs encoding. Check `ClassBuilder.reparentMethod` /
  `setFunctionSignature` flow.
- [ ] **XapArgInst vs XapArgInst_2** — harvest has 2 XapArgInst ASTs
  (`inst.cpp` and `stl_tree.h`). `fewSuffixedConflictRenames` currently
  passes (< 200) but to be sure XapArgInst itself collapses correctly we
  should add an explicit assertion that `XapArgInst_2` does NOT exist in
  the DTM. Likely fine after `4b21a6c` but unverified.
- [ ] **missing DCInst struct (only in /Demangler/)** — DCInst IS in the
  harvest at id `(23, 68)`. After `ffaa808` the polymorphic-base detection
  works, so the vfptr-collision is gone. Need to verify the DCInst Structure
  is at `/inst` (not `/Demangler/...`) in the DTM. Probably already correct
  post-canonicalisation fix; just unverified.

### Quality / scope

- [ ] use ghidra's demangler infrastructure instead of hand-rolled stuff —
  currently `DemanglerReplacer` does its own Itanium-style mangling. Ghidra
  ships `GnuDemangler` which would handle edge cases for free.
- [ ] define structures in the .stab section (with refs to stabstr of course)
    - [ ] add an option in stabimporter to add refs from the stab entries to
      actual code/data locations that they point to
- [ ] use data class as much as possible including built-in hashing — AST
  types and TypeDecl variants are already data classes; remaining target is
  `ContentHash`/`hashDecl` which rolls its own hash. Replacing with
  hashCode() would be cleaner if collision rates stay low.
- [ ] auto thiscall / other calling convention based on stab info? — currently
  every method uses the default cspec. Methods with a `this` first param
  should be flagged thiscall (Windows) / `__regparm(1)` / etc.
- [ ] **`[class-not-struct]` spam (705× remaining)** — per-AST iteration
  calls ClassBuilder.build under each duplicate's cuFile-derived category;
  only the iteration matching `materialiseAll`'s union-of-CUs category
  succeeds. The work is correct; the log noise hides real failures. Fix:
  dedupe ASTs by name with a principled "canonical AST" picker (the naive
  maxByOrNull{methods*100+fields} picked an AST whose vtable struct was
  empty). Try: pick the AST whose cuFile matches the category materialiseAll
  computed for `union(cuFile)`.
- [ ] **`[unresolved-symbol] method` for trivial implicits (931×)** — most
  remaining unresolved methods are auto-generated ctors/dtors/op= for
  trivial structs (`_ZN5div_taSERKS_`, `_ZN6ldiv_tC2Ev`…) that the compiler
  never actually emitted. Could be filtered by detecting "implicit ctor/dtor
  with no body" from the stabs encoding before attempting resolution.

## Issue references

- #40 (Java 21 × Ghidra 11 `ObjectInputFilter.Config.setSerialFilterFactory`
  conflict) — resolved by `ae5145d`. The integration test JVM args now
  declare `-Djdk.serialFilterFactory=ghidra.framework.remote.GhidraSerialFilterFactory`
  at JVM startup, matching Ghidra's own `gradle/javaTestProject.gradle`.
