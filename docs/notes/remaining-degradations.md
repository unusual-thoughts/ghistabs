# Remaining degradations, dangling refs, and failing tests

Snapshot after commit `e6160c5 fix(TypeRegistry): infer base subobject size
from layout gap`. Reproduce with:

```
./gradlew integrationTest \
  --tests 'ghistabs.integration.DegradationDumpIntegrationTest' \
  --tests 'ghistabs.integration.StabsAnalyzerTests'
```

Per-fixture dump output: `build/degradations/<fixture>.txt`.

## Failing regression tests — 30 total

| Test                            | Count | Fixtures                    | Root cause                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Status                                                                                                                                                                                                                                            |
| ------------------------------- | ----- | --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `noEmptyStructs`                | 8     | all 4 × 2 modes             | XRef stubs for legitimately-undefined forward decls (libstdc++ streams, libc opaque types, app-local fwd decls) survive in DTM as zero-length `Structure`s.                                                                                                                                                                                                                                                                                                                                                                                               | **Aspirational** — protocol can't deliver. Test predates the benign-fwd-decl reclassification.                                                                                                                                                    |
| `noAnonymousMaterializedTypes`  | 8     | all 4 × 2 modes             | `makePlaceholder` falls back to `nameOrId = "$id"` for unnamed TypeAsts → empty `[<source>,<n>]`-named Structures leak into the DTM via Ghidra's auto-register-on-first-use as a field type.                                                                                                                                                                                                                                                                                                                                                              | **Real, fixable** — give placeholders a better synthetic name (`XRef.tagName` if available; `<body-kind>_<short-id>` otherwise). The recent `tryGetExisting` materialisation fix removed the dominant source but unnamed XRef-stubs still escape. |
| `atLeastOneVtableStructApplied` | 4     | xmltest × 2, box2d × 2      | xmltest: the gcc 12 inheritance-pseudo-field bug means base classes get parsed as fields, leaving `struct.bases` empty. `firstPolymorphicBase` returns null, so the class is not detected as polymorphic and vtable application is skipped. box2d is C-only and has no vtables to apply.                                                                                                                                                                                                                                                                  | **Real** for xmltest (downstream of gcc 12 quirk); **aspirational** for box2d.                                                                                                                                                                    |
| `inheritanceWasApplied`         | 4     | xmltest × 2, box2d × 2      | Same root cause as the vtable test — pseudo-field bases never reach `replaceAtOffset`, so the `inheritance-applied` counter stays at 0.                                                                                                                                                                                                                                                                                                                                                                                                                   | Same as above.                                                                                                                                                                                                                                    |
| `demanglerStringReplaced`       | 4     | xapasmcsr × 2, appquery × 2 | Not actually about DemanglerReplacer — `assertFalse(goodString!!.isZeroLength)` fails because there IS a non-`/Demangler` `string` Structure but it's zero-length. The `typedef basic_string<char> string;` TypeAst's body wasn't fully materialised through the typedef chain, so it ended up as an empty alias structure. After the recent `tryGetExisting` fix, the body materialises correctly to a typedef pointing at `basic_string<…>` — but the test still fails because a separate `/stabs/string` Structure stub remains alongside the typedef. | **Real** — need to suppress the redundant Structure stub when a typedef alias already exists.                                                                                                                                                     |
| `harvestTest`                   | 2     | box2d × 2                   | "no structs with no field and no method" — gcc 12 emits incomplete stab entries for box2d's vendored deps (imgui / stbtt / GLFW), so empty Struct asts survive.                                                                                                                                                                                                                                                                                                                                                                                           | **Aspirational** for box2d.                                                                                                                                                                                                                       |

## Remaining degradations — per fixture

| Fixture           | Total    | Categories                                                                                                                                                                                                                                                                                     |
| ----------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **xapasmcsr.exe** | **1**    | `base-synthesized` ×1 (CLexStream@+0 → `basic_ifstream<char,…>`, 112-byte placeholder inferred from the layout gap)                                                                                                                                                                            |
| **appquery.exe**  | **2**    | `vtable-failed: truly-missing` ×2 (`runtime_error`, `exception` — libstdc++ vtables live in `libstdc++.dll`, not the binary)                                                                                                                                                                   |
| **box2d_tests**   | **6**    | `body-pointer-pointee` ×5, `xref-stub-in-array-element` ×1                                                                                                                                                                                                                                     |
| **xmltest**       | **34**   | `body-pointer-pointee` ×24, `field-type` ×5, `dangling-ref` ×2, `placeholder-undefined-fields` ×2, `field-dropped` ×1                                                                                                                                                                          |
| **box2d**         | **7325** | `local-untyped` ×3834, `param-untyped` ×2473, `field-type` ×329, `function-ret-untyped` ×266, `body-pointer-pointee` ×199, `array-element` ×85, `field-resolved-to-undefined` ×64, `dangling-ref` ×49, `placeholder-undefined-fields` ×19, `field-dropped` ×6, `xref-stub-in-array-element` ×1 |

### Why the box2d count went up

box2d climbed from 7238 → 7325 after the `tryGetExisting` materialisation
fix — not a regression, just diagnostics catching up. Newly-visible
categories:

- `field-resolved-to-undefined` 0 → 64 (real Undefined leaks now flagged)
- `placeholder-undefined-fields` 6 → 19 (placeholders that materialised
  but every field resolved as Undefined are now properly detected)
- `field-dropped` 0 → 6 (struct-fill exceptions previously masked)
- `dangling-ref` 46 → 49

Each of those was previously hidden behind the empty-stub leak that the
`tryGetExisting` fix closed.

## xapasmcsr's single remaining degradation

```
base-synthesized (1)
  CLexStream@+0 :: Ref unresolved, synthesised 112-byte placeholder
```

`CLexStream:Tt(1,1320)=s328!1,020,(51,22);…` — CLexStream inherits from
type `(51,22)`, which iosfwd binds as
`XRef(STRUCT, "basic_ifstream<char,std::char_traits<char>>")`.
**No record anywhere in the binary's stabs binds the full struct body**:

```
$ rg 'basic_ifstream:T|basic_ifstream:t' src/test/resources/records/xapasmcsr-record.json
(0 matches)
```

gcc only emitted `<iosfwd>`'s forward declaration; the binary never linked
against the full ifstream definition because CLexStream uses ifstream's
methods (via the virtual interface) but not its layout. The base class is
**legitimately external** — the only way to recover the actual struct
layout would be to harvest from libstdc++'s own stabs (which we don't
have).

The size-inference branch fires (since the XRef stub `isZeroLength`) and
synthesises a 112-byte placeholder named `_base_unknown_0` at offset 0 —
matching the layout gap from offset 0 to CLexStream's first non-static
field `LineNo` at bit-offset 896. Field offsets in CLexStream above 112
bytes are correct. The vtable insertion continues to work: `isPoly`
detects via CLexStream's own virtual methods, and `collectInheritedVirtuals`
skips the unresolvable base. The resulting vftable has the right shape
from CLexStream's perspective but is incomplete relative to the actual
binary (inherited slots from ifstream aren't included).

## Remaining dangling Refs — three patterns

Almost every degradation outside box2d's library noise traces back to
**type ids referenced from one CU but never bound by an N_LSYM in that
CU**. Three subpatterns:

### Pattern A — inheritance pseudo-field with name hint (FIXED)

```
XMLElement:T(0,76)=s120XMLNode:(0,25),0,6656;...
```

gcc 12 emits inheritance as a leading pseudo-field with `bitsize > struct
size` (units bug: `bytes * 64` instead of `bytes * 8`). The dangling id is
the base class; the field name carries the base's source-level name.

- Fix: synthesise `XRef(STRUCT, fieldName)` at the dangling id;
  `TypeResolver.lookupByXRef` cross-CU-resolves it to the real struct.
- Recovered: 1/25 on xmltest, ~184 on box2d.
- Confirmed by `objdump -g` rendering the bogus bitsize verbatim and by
  `gdb> ptype XMLText` crashing on the same data.

### Pattern B — anonymous Pointer / Array to never-bound id, no name hint (UNFIXED — dominant)

```
(0,89)=*(0,25)      // Pointer in a surrounding type's body
```

The wrapper (Pointer / Array / etc.) carries no name for what id is.

- xmltest: 24 cases (`tinyxml2.cpp,92→24`, `…173→34`, etc.)
- box2d_tests: 5 cases (all C — `dynamic_tree.c,57→43`, etc.)
- box2d: ~244 (`body-pointer-pointee` + `dangling-ref`)

Possible fixes:

1. **Cross-CU id-shape matching** — for each dangling id `(CU,N)`, look
   for a TypeAst in another CU whose id is also `N` and whose surrounding
   shape matches. Fragile.
2. **Alternative harvest source** — gcc reliably emits DWARF; stabs is
   half-broken in gcc 12.

### Pattern C — field name = field identifier (not type name)

```
DepthTracker._document : Ref([/xml/tinyxml2.cpp,23])
__va_list_tag.gp_offset : Ref([/xml/tinyxml2.cpp,97])
```

Field name doesn't carry the type name.

- xmltest: 5 cases (`field-type`).

Would require name → expected-type mapping for well-known structs
(`__va_list_tag` from `stdarg.h`, …). Not generalizable.

## What's actionable, in priority order

| Priority   | Work                                                                                                                                                                              | Cleared                                                                                                                                                                     |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **High**   | Pattern B (cross-CU id matching, or DWARF-supplementary harvest)                                                                                                                  | xmltest ~24 + box2d_tests ~5 + most of box2d's `body-pointer-pointee` / `dangling-ref` (~244+)                                                                              |
| **High**   | `noAnonymousMaterializedTypes` fix (better placeholder synthetic names)                                                                                                           | 8 test failures + listing readability across all fixtures. The `tryGetExisting` fix already removed the dominant source; remaining anon types come from unnamed XRef stubs. |
| **Medium** | Inheritance pseudo-field → also populate `struct.bases` (not just XRef-synth)                                                                                                     | `inheritanceWasApplied` ×4 + `atLeastOneVtableStructApplied` ×4 on xmltest                                                                                                  |
| **Medium** | `demanglerStringReplaced` — suppress redundant Structure when a typedef alias already exists for the same name                                                                    | 4 test failures                                                                                                                                                             |
| **Low**    | Pattern C (named-field-to-known-type hint table)                                                                                                                                  | 5 entries on xmltest; fragile                                                                                                                                               |
| **No fix** | CLexStream's `basic_istream` base (xapasmcsr); libstdc++ vtables in DLL (appquery); box2d's vendored stab-less deps; xmltest's `field-dropped` template-specialization collisions | 1 + 2 + ~7000 + 1                                                                                                                                                           |

The two highest-leverage actionable items remain:

1. **Pattern B recovery** — clears most pointer-pointee dangles across all
   ELF fixtures.
2. **Inheritance pseudo-field → also populate `struct.bases`** — the
   current fix synthesises the dangling Ref's XRef-stub but leaves the
   consuming struct's `bases` list empty, so the materialiser's
   `BaseInsertionPlanner` and `firstPolymorphicBase` never see the
   inheritance. Clears 8 vtable/inheritance test failures on xmltest in
   one move.
