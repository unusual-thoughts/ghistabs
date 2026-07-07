# Harvest canonical keying

## Three public maps

```kotlin
val byId: Map<GlobalTypeId, TypeAst>
val byName: Map<String, List<TypeAst>>       // raw stabs name; cross-CU bucket
val byCanonicalKey: Map<Pair<CategoryPath, String>, CanonicalGroup>
```

`CanonicalGroup`:
```kotlin
data class CanonicalGroup(
  val key: Pair<CategoryPath, String>,
  val members: List<TypeAst>,
  val winner: TypeAst,
)
```

Internal during build: `astsByGhidraName` (transient, discarded).

## Build order

```
A. byId from harvest.
B. byName from byId, raw stabs-name only.
C. group registerable ASTs by ghidraName (transient).
D. per ghidraName: Attribution.categoryFor(name, ∪ definingCUs).
E. bucket into byCanonicalKey: (category, ghidraName) → ASTs.
F. per group: pick winner, emit diagnostics, drop intermediates.
```

## What counts as "registerable"

Bodies that produce a stable `(CategoryPath, name)` slot in the DTM:
`Struct` (covers struct/union/class via `kind`), `Enum`, `Typedef`.
Everything else (Pointer, Reference, FunctionT, InlineDef, Method, …)
is materialised on demand via `byId`, never indexed by canonical key.

## What's certain vs heuristic

- `GlobalTypeId` is the only guaranteed-unique identifier (by construction).
- Stabs name is unique *within a CU* only.
- `ghidraName` is a sanitized projection — distinct stabs names can collide.
- `CategoryPath` is heuristic — multiple unrelated types can legitimately
  share `/headers-untracked/Foo.h`.

So multi-hash under `(cat, ghidraName)` is INFO, not WARN:
more often our coarseness than program ODR.
Multi-kind (struct AND union at the same key) is WARN — that's a real bug.

## byName broadening (kills `structAstsByName` asymmetry)

Today: `structAstsByName` indexes only `TypeDecl.Struct`. XRefs with
`kind=ENUM` silently miss. New `byName` includes any AST with a non-empty
stabs name; `getByXRef` filters by `xref.kind` (matches `Struct.kind` for
struct/union/class, `Enum` body for enum).

`structAstsByBaseTag` collapses into the same scheme: same name index,
template-args-stripped key, kind-filtered.

## TypeRegistry / "TypeResolver" relevance

Once `byCanonicalKey` owns the registration decision:

- `TypeRegistry.byPath` (hash-keyed first-writer-wins) goes away — dedup
  decided upstream with full provenance.
- `TypeRegistry.byHash` (cross-CU canonical) is subsumed: members of a
  CanonicalGroup share a winner.
- `materialiseAll`'s placeholder pre-seeding still needed for cycle
  breaking. `resolve`/`materialiseBody` still needed for body rendering.
- `dataTypeFor` (decl → DataType) is the actual "resolver" surface;
  stays. `harvest.getByXRef` (name → AST) also stays, broadened.

Net: `TypeRegistry` shrinks to placeholder allocation + body
materialisation + a thin `byId` cache for Ref resolution. The bookkeeping
of "which AST won this (cat, name) slot" moves to harvest.

## Status (render-backlog §22)

- **Content-merge folded in.** `byCanonicalKey` is one pipeline: bucket XRef-targets into
  `(category, ghidraName)` slots (`classifyGroup` picks each winner), then unify slots whose winners
  are content-equivalent and share exactly one named `ghidraName`. The old standalone
  `mergeContentEquivalentGroups` second pass is gone (the fold is provably equivalent).
- **Attribution keys stay raw.** `keyForAst` reads raw `id.source`; the `multiSourceHeaderHints`
  input to `Attribution` is voted on raw N_SOL spellings (a pure function, computed in the Harvester
  *before* render-source canonicalization, stored raw on `Harvest`). §15 path-canonicalization is a
  render-only concern applied at the data layer (`Harvest.sourceCanonicalization`); it never keys the
  DTM. Type dedup across header spellings is content-based, not path-based, so canonical categories
  add nothing and were reverted once for regressing (see §15/§20).
