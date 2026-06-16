# Phase 4: Category attribution fix

**Goal:** Diagnose and fix mis-attribution of user types to `/std/...`. Reference symptom: `XapArgInst` in
`xapasmcsr.exe`. Investigation-first; only modify `STD_MARKERS`/logic if the trace proves a bug.

**Architecture:** Add a per-call trace into `StabsDiagnostics` for every `categoryFor()` call whose result lands under
`/std/...`. Run analyzer once on `xapasmcsr.exe`, inspect trace for `XapArgInst`, fix if it's a bug, document if it's
expected stabs data.

**Tech Stack:** Kotlin.

**Testing convention:** All new tests follow
`docs/implementation-plans/2026-05-29-stabs-importer-fixes/testing-convention.md` — `Attribution.categoryFor` is already
pure; tests are pure unit. The integration trace is captured during a real headless run.

**Scope:** 4 of 8 phases.

**Codebase verified:** 2026-05-30

---

## Acceptance Criteria Coverage

### stabs-importer-fixes.AC3: User types categorised correctly

- **stabs-importer-fixes.AC3.1 Success:** `XapArgInst` in `xapasmcsr.exe` is placed under a project-derived category (
  not `/std/include/...`).
- **stabs-importer-fixes.AC3.2 Edge:** Genuine stdlib types (e.g. `std::basic_string`, `std::pair`) continue to land
  under `/std/...`; no false negatives.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->

### Task 1: Trace categoryFor std-routing decisions

**Verifies:** None (diagnostic infrastructure)

**Files:**

- Modify: `src/main/kotlin/ghistabs/builder/Attribution.kt:27-57`

**Implementation:**
Extend `categoryFor()` signature to accept an optional `diagnostics: StabsDiagnostics? = null`. Inside, at the moment
the STD_MARKERS branch (line 33) decides `/std/<stdMatch>`, call:

```kotlin
diagnostics?.recordAttributionTrace(
    typeName = typeName,
    definingCUs = definingCUs,
    matchedCU = definingCUs.first { stdBasename(it) != null },
    routedTo = "/std/$stdMatch",
)
```

Add `recordAttributionTrace(...)` to `StabsDiagnostics`: stores per-type tuples in a bounded list (cap 200), incremented
under counter `"attribution-routed-std"`.

The callers of `categoryFor` (currently the default lambda at `TypeRegistry.materialiseAll` line 137 and
`TypeRegistry.resolve` line 240, plus the test) need to pass `ctx.diagnostics`. Thread `ctx` through the `attribution`
lambda — change the lambda type to `(String, Set<String>) -> CategoryPath` to keep backward compat, but wrap the default
at the call site with the diagnostics capture.

**Testing:**

- Extend `AttributionTest.kt`: add `testTraceRecordedOnStdRoute` — pass a `StabsDiagnostics` instance, call
  `categoryFor("XapArgInst", setOf("/usr/include/c++/3.4.4/string"))`, assert the trace bucket has exactly one entry
  naming `XapArgInst` and `/usr/include/c++/3.4.4/string` as the matched CU.

**Verification:**

- Run: `./gradlew test --tests "ghistabs.materialize.AttributionTest"`
- Expected: passes; no existing test breaks.

**Commit:** `feat(builder): trace categoryFor std-routing decisions`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->

### Task 2: Diagnose XapArgInst via integration trace

**Verifies:** None (investigation step)

**Files:**

- Modify: `src/test/kotlin/ghistabs/XapasmcsrIntegrationTest.kt:90-104` (real-binary test)

**Implementation:**
After the analyzer runs, query `ctx.diagnostics` attribution-trace bucket for entries with `typeName == "XapArgInst"`.
If non-empty, write to `build/test-output/xapargInst-attribution-trace.txt` (the test does NOT fail; it produces an
artifact). If empty, write `"XapArgInst not routed to /std/* in this run"` and the test passes.

This task IS read-only diagnostic output — the FIX comes in Task 3 informed by what the trace reveals.

**Verification:**

- Run: `./gradlew integrationTest --tests "ghistabs.XapasmcsrIntegrationTest"` (requires binary)
- Expected: artifact written; test does not fail.

**Commit:** `test(builder): dump XapArgInst attribution trace`
<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (task 3) -->
<!-- START_TASK_3 -->

### Task 3: Fix attribution bug OR document as expected

**Verifies:** stabs-importer-fixes.AC3.1, stabs-importer-fixes.AC3.2

**Files:**

- Modify: `src/main/kotlin/ghistabs/builder/Attribution.kt` (if the trace reveals a bug)
- Modify: `src/test/kotlin/ghistabs/builder/AttributionTest.kt` (regression)
- Modify: `docs/implementation-plans/2026-05-29-stabs-importer-fixes/notes-attribution.md` (NEW — if outcome is "
  expected stabs data")

**Implementation:**
Based on the Task 2 trace output, choose ONE branch:

**Branch A — Bug in STD_MARKERS or stdBasename:**

- The trace shows `XapArgInst` matched STD_MARKERS via some CU path that should NOT be considered stdlib (e.g. a project
  file with `c++` as a directory name like `/proj/src/c++_helpers/foo.cpp`). Tighten the regex by requiring the matched
  directory to be preceded by `/usr/`, `/lib/`, or `/include/` — i.e. change to
  `Regex("""/(usr|lib|include)/[^/]*/(mingw|cygwin|c\+\+|bits)/""")` OR allowlist via additional path-component checks.
- Add a regression test: `testNoFalsePositiveOnProjectCxxDir` with a CU path matching the false-positive pattern, assert
  it does NOT route to `/std/`.

**Branch B — Bug in CU canonicalisation (Phase B residue):**

- The trace shows `XapArgInst` has a defining CU like `(canonical-c++/3.4.4/string)` because the include-table from
  Phase B mis-attributed it. Fix in Phase B's `IncludeContext.canonicalTypeId` — when a type is defined in a CU's own
  source file (not under BINCL), don't canonicalise its CU path through the include map. Add a regression
  `IncludeContextTest` case.

**Branch C — Stabs data really say so:**

- The trace shows that gcc 3.4 / Cygwin really emits `XapArgInst`'s defining CU as the stdlib path because of an
  aggressive include unit (e.g. `xap_arg_inst.h` is included from `<string>` somehow). Document in
  `notes-attribution.md`: list the affected types, the CU paths, and the rationale (link to xapasmcsr's source if
  accessible). The `XapArgInst` AC is then satisfied by a manual override list:
  ```kotlin
  private val PROJECT_OVERRIDE_NAMES = setOf("XapArgInst", /* … */)
  ```
  consulted FIRST in `categoryFor()` — if `typeName in PROJECT_OVERRIDE_NAMES`, route to a configured `/proj/<name>`
  category, log `attribution-override` for visibility.

In all three branches, add `testXapArgInstNotInStd` assertion in `AttributionTest.kt` (or `XapasmcsrIntegrationTest.kt`)
that verifies the final attribution.

**Testing:**

- Run the new regression test from whichever branch was taken.
- Run the full `AttributionTest` suite to confirm no false negatives on stdlib types (the existing `testCppStdBasename`,
  `testMingwStdBasename` must still pass).

**Verification:**

- Run: `./gradlew test --tests "ghistabs.materialize.AttributionTest"`
- Expected: passes.
- Run: `./gradlew integrationTest --tests "ghistabs.XapasmcsrIntegrationTest"`
- Expected: `XapArgInst` lands under a non-`/std/` category.

**Commit:** `fix(builder): attribute XapArgInst correctly` OR
`docs(builder): document attribution edge case for stabs from Cygwin gcc 3.4`
<!-- END_TASK_3 -->
<!-- END_SUBCOMPONENT_B -->

**Phase 4 done when:**

- Trace artifact for `XapArgInst` produced and analysed.
- Either: regex/logic fix lands AND regression test passes; OR override list lands AND notes document the rationale.
- Existing stdlib attribution tests (`testCppStdBasename`, `testMingwStdBasename`) still pass — no false negatives.
- `attribution-routed-std` counter visible in diagnostics summary.
