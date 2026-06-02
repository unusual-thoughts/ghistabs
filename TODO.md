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

## Open

### Likely still-broken
- [ ] **globals still not typed (eg `_BranchInstructions` which should be named
  `BranchInstructions`)** — log shows `[unresolved-symbol] global BranchInstructions`.
  Root cause: the stabs N_GSYM gives the unmangled C name `BranchInstructions`,
  but the PE symbol table on Windows MinGW prefixes externals with `_` (so
  Ghidra has `_BranchInstructions`). `AddressResolver` only tries the exact
  stab name. Fix: also try `_<name>` (and stdcall-mangled `<name>@<n>`)
  as fallback symbol-name candidates when the bare name doesn't resolve.
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
- [ ] full stabs parser? any tokens ignored? — `[drop-record]` fires 23 901
  times. Most are probably benign (irrelevant stab types like N_OPT) but
  needs a sweep to confirm none are dropping useful structural data.
- [ ] use data class as much as possible including built-in hashing — AST
  types and TypeDecl variants are already data classes; remaining target is
  `ContentHash`/`hashDecl` which rolls its own hash. Replacing with
  hashCode() would be cleaner if collision rates stay low.
- [ ] auto thiscall / other calling convention based on stab info? — currently
  every method uses the default cspec. Methods with a `this` first param
  should be flagged thiscall (Windows) / `__regparm(1)` / etc.
- [ ] logging / diag — broader sweep: 705 spurious `[class-not-struct]`
  messages come from per-AST iteration (each duplicate AST tries
  ClassBuilder.build under its own cuFile-derived category, and only the
  one matching materialiseAll's union-of-CUs category succeeds). The work
  is correct (the same name succeeds at least once) but the log noise hides
  real failures. Fix: dedupe ASTs by name in the ClassBuilder loop using
  the most-complete body and the union of cuFiles — *attempted, reverted*
  because the "most-complete" heuristic picked an AST whose vtable struct
  ended up empty. Needs a more principled "canonical AST" picker.

## Issue references
- #40 (Java 21 × Ghidra 11 `ObjectInputFilter.Config.setSerialFilterFactory`
  conflict) — resolved by `ae5145d`. The integration test JVM args now
  declare `-Djdk.serialFilterFactory=ghidra.framework.remote.GhidraSerialFilterFactory`
  at JVM startup, matching Ghidra's own `gradle/javaTestProject.gradle`.
