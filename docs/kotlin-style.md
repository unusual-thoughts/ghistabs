# Kotlin Style Guide

House style for `ghidra-stabs`. The goal is idiomatic, concise Kotlin that
reads like the surrounding code. Generated code that ignores this tends to be
verbose, imperative, and over-commented — fix it to match here.

**The overarching rule: aim for compactness and concision.** The fewest lines,
fewest intermediates, fewest comments that still read clearly. Every section
below is an instance of this. When two versions work, ship the shorter one —
unless it's shorter by being cryptic. Compact, not golfed.

ktlint (`ktlintCheck` / `ktlintFormat`) is authoritative for formatting;
everything below is about what ktlint can't see.

---

## 1. Expression-first

Prefer expression bodies, expression `when`/`if`, and returning values over
mutating accumulators.

```kotlin
// no
fun kind(t: Type): String {
    var k = "?"
    if (t.isStruct) k = "struct" else if (t.isEnum) k = "enum"
    return k
}

// yes
fun kind(t: Type) = when {
    t.isStruct -> "struct"
    t.isEnum -> "enum"
    else -> "?"
}
```

Single-expression function → `= expr`, no block, no `return`.

## 2. Build with the pipeline, not the loop

Reach for `map`/`filter`/`associateBy`/`groupBy`/`mapNotNull`/`sumOf` before a
`for` + `mutableListOf`. Use `buildList`/`buildString`/`buildMap` when a pipeline
would be contorted but you still want a single expression.

```kotlin
// no
val out = mutableListOf<String>()
for (f in fields) if (!f.isStatic) out += "${f.name};"

// yes
val out = fields.filterNot { it.isStatic }.map { "${it.name};" }
```

Index arithmetic is a smell. `mapIndexed`, `withIndex`, `zipWithNext`,
`windowed`, `chunked`, `flatMap` usually replace it. Keep an explicit indexed
loop only when you genuinely index *other* structures by the same `i`.

Build maps declaratively too: `associateBy` / `associateWith` / `buildMap`, and
`groupingBy { … }.eachCount()` for a tally — not `for` + `mutableMap`.

Use `Sequence` (`asSequence()`, `sequenceOf(...).max()`) for long or lazy
chains; a two-step `.map {}.filter {}` on a small list stays a `List`.

## 3. Null handling

`?.`, `?:`, `?.let`, `?.takeIf`, `firstOrNull`, `getOrNull`, `orEmpty()`.
Never `!!`. Never an `if (x != null)` pyramid where `?.let {}` / `?:` reads
straight through.

```kotlin
val addr = when {
    s.rawValue != 0L -> factory.getAddress(s.rawValue)
    else -> symbolTable.getSymbols(name).firstOrNull()?.address
}
```

`?.let { ... } == true` is the idiom for "non-null AND predicate".

## 4. Scope functions — sparingly, correctly

`let` (transform / null-guard), `apply` (configure & return receiver), `also`
(side effect in a chain), `run`/`with` (group calls on one receiver). One level
deep. If nesting scope functions or you can't tell `it` from `this` at a glance,
pull a named local or function instead.

## 5. Naming, scope, immutability

- `val` by default; `var` only for a genuine accumulator (e.g. `prevEnd` in the
  span fold). **Avoid mutation**: prefer immutable `data class` + `.copy()` over
  mutating fields, and a pure pipeline that returns a new value over one that
  edits a shared collection in place.
- `private` by default; widen only when something outside needs it.
- Descriptive names, no Hungarian, no `l`/`ll`/`tmp`. Lambda `it` is fine one
  level deep; name the parameter when nested or non-obvious.
- Destructure where it clarifies: `for ((line, addrs) in map)`,
  `val (f, start, _) = range`.
- Boolean call args get named form: `renderSkeleton(source, decompile = true)`.
- Group related constants with a shared prefix (`OPT_PLATE_COMMENTS`,
  `OPT_VTABLES`) rather than scattering ad-hoc names.

## 5b. Delegates

Use property delegation to express intent the language already has a hook for:

- `by lazy { … }` for an expensive derived value computed once on first access —
  the idiomatic replacement for a nullable backing field + null-check-and-init.
- `Delegates.observable` / `vetoable` for a `var` that must react to writes.
- Map-backed properties (`val name: String by map`) when modelling dynamic
  records. Custom `ReadOnlyProperty` when several properties share a derivation.

Reach for a delegate before hand-rolling a getter with caching or validation.

## 6. Types

- `data class` for value aggregates (`RawSpan`, `FuncRange`). Get
  `equals`/`hashCode`/`copy` for free — don't hand-roll them.
- `sealed`/`enum` + exhaustive `when` (no `else`) for closed hierarchies, so a
  new case is a compile error at every match site. `TypeDecl` is the model.
  Prefer `sealed interface` when the cases share no state or a case must belong
  to more than one hierarchy; `sealed class` when there's common stored data.
- Default arguments over overloads.
- Multi-line string literals use triple quotes + `trimIndent()` (regexes,
  templates), not `"…\n" + "…"` concatenation.

## 6a. Extensions and operators

Attach vocabulary to types you don't own instead of writing free helpers that
take the receiver as an argument. Shared Ghidra extensions live in
`GhidraExtensions.kt`; feature-local ones sit next to their use
(`Address.render`, `TypeDecl.render` in `render/`).

```kotlin
val Program.functions get() = functionManager.getFunctions(true).asIterable()
fun String.nullIfEmpty() = ifEmpty { null }
operator fun Address.plus(rhs: Long): Address = addNoWrap(rhs)      // currentAddr + 10
operator fun Address.rangeTo(rhs: Address) = AddressRangeImpl(this, rhs)
```

- Prefer an extension **getter** (`get() = …`) over a `getX()` method for a
  derived, side-effect-free value.
- Overload operators (`plus`, `minus`, `rangeTo`, `get`, `contains`) when they
  read naturally — `addr + 10`, `a..b`, `data[i]`, `data["field"]`.
- Wrap resource/ceremony patterns in a generic lambda extension:
  `DomainObject.runTransaction(desc) { … }` beats hand-rolled
  `startTransaction`/`endTransaction` at every call site.

## 6b. Companion objects

Use a `companion object` for factory/lookup logic tied to a type — not a
grab-bag of statics. The enum-from-code lookup is the canonical shape:

```kotlin
companion object {
    private val byCode = entries.filter { it != UNKNOWN }.associateBy { it.code }
    fun fromCode(b: Int) = byCode[b and 0xFF] ?: UNKNOWN
}
```

Precompute the map once in the companion; don't linear-scan `entries` per call.

## 6c. Value classes (newtypes) — useful, don't overuse

`@JvmInline value class Offset(val bits: Long)` wraps a primitive with a distinct
type at zero runtime cost, so you can't pass a line number where an address is
expected — worthwhile in this address/id-heavy code.

```kotlin
@JvmInline value class Offset(val value: Long)
```

But **don't newtype reflexively.** Reach for one only when the raw type is
genuinely confusable at a call site or an invariant rides on it. A `value class`
around a string that's only ever a string is ceremony. Rule of thumb: introduce
it when two same-primitive values could be swapped by mistake, not before.

## 7. Comments: why, not what — and never mixed into code

This is the **single most-reapplied correction to generated code** in this repo:
across the `trim ass-covering comments` passes, roughly two-thirds of the comment
volume was deleted. Write far fewer comments than feels natural. Concretely, the
things that get cut every time — don't write them:

- **Per-line narration** — `// increment the counter` above `count++`.
- **Multi-paragraph rationale** — one dense sentence, not a section.
- **Encoding/format example dumps** pasted into the body (`XMLNode:T(0,81)=s112…`).
  A single canonical example in the type's KDoc is plenty; the rest is noise.
- **Hedging / ass-covering** — "this should be safe", "in case …", "note that we".

A comment earns its place only by explaining a non-obvious *why* — a gcc quirk,
an invariant, a decision the code can't state itself. If the code already says
it, delete the comment.

Keep comments *structurally* separate from code where the design allows it —
`Fragment(indent, code, comment)` in the renderer is the concrete example: the
provenance annotation is a field, not spliced into the code string, so a `//`
can never swallow code and the two can be dropped/rewritten independently.

KDoc (`/** … */`) on a type or non-trivial function states its contract in a
sentence or two. Skip KDoc on self-evident members. Commit messages carry
history — don't leave `// was: …` / `// TODO(old)` fossils in the source.

## 8. Preconditions and errors

`require`/`check`/`error("…")` for invariants; `runCatching { }.getOrNull()`
when a failure is an expected "no result" (a decompile that doesn't converge).
Don't wrap half a function in `try` to smother a bug — let it throw.

Anything `Closeable`/disposable goes through `.use { }` (loaders, transactions,
`DecompInterface`) — deterministic cleanup over a hand-written `try/finally`.

## 8a. Tests: only when non-trivial

Add a test only when it can fail for a real reason — non-obvious logic, a fixed
bug, an edge case (empty/overflow/cycle), an invariant worth pinning. Don't test
getters, one-line delegations, or that a `data class` copies. A test that can
only pass is noise that slows the suite and rots on rename. Prefer a Kind-1 pure
unit (e.g. `Layout`/`FunctionSpans`) over a headless-Ghidra test when the logic
is pure; never add mocks (see the memory notes).

## 9. Anti-patterns seen in generated code

| Instead of | Write |
| --- | --- |
| `for` + `mutableListOf` accumulator | `map` / `filter` / `mapNotNull` / `buildList` |
| manual `i` indexing | `mapIndexed`, `zipWithNext`, `withIndex` |
| `if (x != null) { … }` nesting | `x?.let { }` / `?:` |
| `!!` | `?:` with a real fallback or `error(...)` |
| block body that just builds & returns one value | expression body `=` |
| a comment restating the code | delete it, or explain the *why* |
| hand-written `equals`/`hashCode` | `data class` |
| `else -> {}` swallowing a sealed `when` | exhaust the cases |
| one-use helper extracted "for clarity" | inline it; extract only at the 2nd caller |

When in doubt: shorter, more declarative, fewer intermediates, fewer comments.
Match the density and idiom of the file you're editing.

## 10. Moves from the codebase's own simplify/style passes

Concrete rewrites the maintainer has made by hand (`3a40357` "simplify",
`86a5a3c` "lint/code style") — apply them proactively:

- **Query the collection view, don't rebuild it.** `map.values` / `map.keys` /
  `map.keys.size`, not `map.map { it.x }` then `.toSet().size`. If you find
  yourself re-deriving a set/list a `Map` already holds, use the `Map`.
- **Pick the data structure for the access pattern.** A `List<TypeAst>` that's
  only ever looked up by id becomes a `Map<GlobalTypeId, TypeAst>` — dedup and
  O(1) lookup fall out for free.
- **Slim signatures.** Drop a parameter that's threaded through but never used,
  or that the callee can derive. Fewer args > "might need it later".
- **Collapse short `when` arms and `else` blocks** to one line;
  `else -> log(x)` not `else -> { log(x) }`.
- **Computed getter property** over a stored, hand-maintained field:
  `val ghidraName get() = SymbolUtilities.replaceInvalidChars(name, false)`.
- **Delete dead guards** — a `if (name == "SomeDebugThing")` probe or an empty
  class left over from a refactor is noise; remove it.
- **One line when it fits.** Short param lists, `data class` bodies, and simple
  assignments go on one line (ktlint enforces the wrapping, not the collapsing).
- **Adapt via a secondary constructor**, not an external factory:
  `data class StabsOptions(…) { constructor(opts: Options) : this(…) }` — build
  the value object from raw input at the type, not at every call site.
- **`filterIsInstance<T>()`** to select-and-cast a collection in one step.
- **`.single()` / `.singleOrNull()`** when exactly one element is the invariant —
  it asserts the expectation, unlike `first()`/`[0]`.
- **Collapse a `when` whose arms all do the same thing** to one expression (a
  plain cast when the branches were only narrowing a type).
- **`inline fun <reified T>`** for a generic accessor that needs the runtime type.

## 11. File and function size

- **No long functions.** A function that scrolls is doing too much — split it
  into named steps (the renderer's `render()` calls `emitTypedefs()`,
  `emitGlobals()`, … each a self-contained pass). A reader should see the whole
  shape on one screen.
- **Local functions capture, don't thread.** A helper used only inside one
  function and needing its locals should be a `fun` declared inside it (closing
  over them), not a private method taking them all as params — see `suffix()` in
  `emitParamsAndLocals`.
- **No one-class files — this isn't Java.** Group related declarations in a file
  named for the concept, not the class: `Layout.kt` holds `Fragment` +
  `TargetLine` + `Canvas`; `FunctionSpans.kt` holds `RawSpan` + `FuncRange` +
  `FunctionSpans`. Extensions, small sealed members, and helper types live beside
  what they serve. Split a file when it stops being one concept, not per type.
