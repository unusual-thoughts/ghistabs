# Human Test Plan — Stabs Algorithm Audit (2026-06-09)

Generated from test-analyst coverage pass at HEAD `e8de739`.

**Automated coverage:** 11/11 automatable criteria PASS.  
**Manual verification required:** AC1.4, AC2.1–2.5, AC3.6, AC4.1–4.4.

---

## Prerequisites

- Repo at `/home/riton/git/bouse/ghidra-stabs` checked out at HEAD `e8de739`
- JDK + Gradle wrapper functional
- `./gradlew test` exits 0 (baseline)
- Editor for reading `.md` and `.kt` files

---

## Phase A: Automated test re-verification

| Step | Action | Expected |
|------|--------|----------|
| A1 | `./gradlew test --tests "ghistabs.parser.ParserPrimitiveTest"` | Exit 0; 11 tests PASSED |
| A2 | `./gradlew test --tests "ghistabs.parser.ParserClassTest"` | Exit 0; 7 tests PASSED including testMethodNoParametersVoidSentinel and testMethodImplicitThisPointer |
| A3 | `./gradlew test --tests "ghistabs.parser.ParserBugfixTest"` | Exit 0; testStructXRef, testUnionXRef, testEnumXRef, testDeeplyNestedInlineDef PASSED |
| A4 | `./gradlew test --tests "ghistabs.parser.HarvesterGlobalizeTest"` | Exit 0; 7 tests PASSED |
| A5 | `./gradlew test --tests "ghistabs.parser.HarvesterAppendAstsTest"` | Exit 0; 4 tests PASSED |
| A6 | `./gradlew test --tests "ghistabs.parser.HarvesterPassATest"` | Exit 0; 10 tests PASSED |
| A7 | `./gradlew test --tests "ghistabs.parser.HarvesterGapTest"` | Exit 0; active tests PASSED, D2/D3/D7 @Disabled skipped |
| A8 | `./gradlew test --tests "ghistabs.parser.IncludeContextTest"` | Exit 0; 9 tests PASSED |
| A9 | `./gradlew test` (no filter) | BUILD SUCCESSFUL; no FAILED; pre-existing @Disabled skipped (AC4.5) |

---

## Phase B: Reference document (AC2)

| Step | Action | Expected |
|------|--------|----------|
| B1 | Open `docs/notes/stabs-canonicalization.md` | File exists, ≥9 H2 sections |
| B2 | `grep -c "^## " docs/notes/stabs-canonicalization.md` | Output: 9 (AC2.1) |
| B3 | Read each H2 heading; confirm 9 required titles: (1) Stab record forms, (2) Namespace model, (3) Type-ID identity model, (4) Cross-CU deduplication, (5) Deep ID resolution, (6) Forward cross-references, (7) Untouched algorithm parts, (8) Commit review and deviation table, (9) Pipeline architecture and segmentation audit | All 9 present (AC2.1) |
| B4 | Read top-to-bottom; for every paragraph asserting gdb/BFD behavior, look for an inline citation to a function in `stabsread.c` / `bfd/stabs.c` or a stabs PDF section reference | No unsourced gdb/BFD claims (AC2.2, AC2.5) |
| B5 | Locate section 8.4 deviation table | Has rows D1–D7 minimum, each rated `correct`, `incomplete`, `needs-fix`, or `vestigial` (AC2.3) |

---

## Phase C: KDoc coverage (AC2.4)

| Step | Action | Expected |
|------|--------|----------|
| C1 | Open `src/main/kotlin/ghistabs/parser/Harvest.kt`; locate `class Harvester` | Non-empty KDoc (`/** ... */`) above declaration |
| C2 | Same file: locate `fun globalize(` | Non-empty KDoc above declaration |
| C3 | Same file: locate `fun appendAsts(` | Non-empty KDoc above declaration |
| C4 | Open `src/main/kotlin/ghistabs/parser/IncludeContext.kt`; locate `class IncludeContext` | Non-empty KDoc |
| C5 | Same file: locate `fun sourceFor(` | Non-empty KDoc |
| C6 | Same file: locate `class HeaderRegistry` | Non-empty KDoc |
| C7 | Same file: locate `fun recall(` inside `HeaderRegistry` | Non-empty KDoc |

---

## Phase D: No log-derived assertions (AC1.4, AC3.6)

| Step | Action | Expected |
|------|--------|----------|
| D1 | `grep -n "from log\|captured from\|xapasmcsr run" src/test/kotlin/ghistabs/parser/ParserPrimitiveTest.kt src/test/kotlin/ghistabs/parser/ParserClassTest.kt src/test/kotlin/ghistabs/parser/ParserBugfixTest.kt` | No matches (AC1.4) |
| D2 | Same grep against `HarvesterGlobalizeTest.kt`, `HarvesterAppendAstsTest.kt`, `HarvesterPassATest.kt`, `HarvesterGapTest.kt` | No matches (AC3.6) |
| D3 | Spot-check 3 expected-value constructions in each file; verify the literal stabs string and expected AST are derivable from the stabs PDF or `stabs-canonicalization.md` | All expected values justified from spec |

---

## Phase E: TODO.md retriage (AC4)

| Step | Action | Expected |
|------|--------|----------|
| E1 | Open `TODO.md` | File exists |
| E2 | Review the Phase 8 Done section; for each item listed, confirm the corresponding TODO entry is marked closed | All items addressed by phases 1–7 are closed (AC4.1) |
| E3 | Search TODO.md for items touching: include-stack, nested-Ref, forward-EXCL divergence | Each open item contains a concrete citation: stabs PDF §-number, `stabsread.c` function name, or D-ID from deviation table (AC4.2) |
| E4 | Search TODO.md for vestigial flags on: `rawByIdSnapshot` (D5), `collidingAsts` downstream consumer (D6), `preSeedHeaders()` two-pass rationale (D3), stale `Attribution` routing (D2), `AttributionTraceDump` usage (D7) | All five items flagged with [vestigial], [documented], [stale], or [incomplete] annotations (AC4.3) |
| E5 | Search TODO.md for a forward-EXCL placeholder divergence entry (D1) | At least one D1-tagged entry present (AC4.4) |

---

## Phase F: D-ID parity self-check (AC3.4)

| Step | Action | Expected |
|------|--------|----------|
| F1 | `grep -o "D[0-9]\+" docs/notes/stabs-canonicalization.md \| sort -u` | Output: D1 D2 D3 D4 D5 D6 D7 |
| F2 | `grep -o "D[0-9]\+" src/test/kotlin/ghistabs/parser/HarvesterGapTest.kt \| sort -u` | Output: D1 D2 D3 D4 D5 D6 D7 (matches F1) |
| F3 | Open HarvesterGapTest.kt; for each `correct` row in deviation table, confirm a `// D<n>: correct per spec — no test needed` comment exists | Comments present for every `correct` D-ID |

---

## End-to-End: Audit consistency

Purpose: validate that every deviation in the canonicalization doc has a paired test outcome and a TODO disposition.

1. Open `docs/notes/stabs-canonicalization.md` section 8.4.
2. For each row D1..D7, note rating (`correct` / `incomplete` / `needs-fix` / `vestigial`).
3. Open `HarvesterGapTest.kt`; for each D-ID confirm the corresponding test (active, @Disabled, or `correct`-comment) matches the row's rating.
4. Open `TODO.md`; for each `incomplete` / `needs-fix` / `vestigial` D-ID, confirm a TODO entry cites that D-ID.
5. Expected: every D-ID appears consistently in all three locations with matching disposition.

---

## Traceability

| Acceptance Criterion | Automated Test | Manual Step |
|----------------------|----------------|-------------|
| AC1.1 Type-form coverage | ParserPrimitive/Class/BugfixTest (A1–A3) | — |
| AC1.2 Method #-form edge cases | ParserClassTest (A2) | — |
| AC1.3 Deeply nested InlineDef | ParserBugfixTest (A3) | — |
| AC1.4 No log-derived parser assertions | — | D1, D3 |
| AC2.1 9 sections present | `grep` count (B2) | B1, B3 |
| AC2.2 Spec citations | — | B4 |
| AC2.3 Deviation table D1–D7 | — | B5 |
| AC2.4 KDoc coverage | — | C1–C7 |
| AC2.5 No unsourced claims | — | B4 |
| AC3.1 HarvesterGlobalizeTest | A4 | — |
| AC3.2 HarvesterAppendAstsTest | A5 | — |
| AC3.3 HarvesterPassATest | A6 | — |
| AC3.4 HarvesterGapTest | A7 + F1–F2 | F3 |
| AC3.5 IncludeContextTest BINCL re-entry | A8 | — |
| AC3.6 No log-derived harvester assertions | — | D2, D3 |
| AC4.1 Done items closed | — | E2 |
| AC4.2 Spec citations on open items | — | E3 |
| AC4.3 Vestigial items flagged | — | E4 |
| AC4.4 Deviation TODO entries present | — | E5 |
| AC4.5 Full test suite green | `./gradlew test` (A9) | — |

---

## Relevant files

- `docs/notes/stabs-canonicalization.md`
- `TODO.md`
- `src/main/kotlin/ghistabs/parser/Harvest.kt`
- `src/main/kotlin/ghistabs/parser/IncludeContext.kt`
- `src/test/kotlin/ghistabs/parser/ParserPrimitiveTest.kt`
- `src/test/kotlin/ghistabs/parser/ParserClassTest.kt`
- `src/test/kotlin/ghistabs/parser/ParserBugfixTest.kt`
- `src/test/kotlin/ghistabs/parser/HarvesterGlobalizeTest.kt`
- `src/test/kotlin/ghistabs/parser/HarvesterAppendAstsTest.kt`
- `src/test/kotlin/ghistabs/parser/HarvesterPassATest.kt`
- `src/test/kotlin/ghistabs/parser/HarvesterGapTest.kt`
- `src/test/kotlin/ghistabs/parser/IncludeContextTest.kt`
