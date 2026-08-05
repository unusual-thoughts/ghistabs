# Layout rewrite: claim-and-resolve, front-positioned provenance

Draft. Supersedes the `Fragment`/`TargetLine` model in `render/Layout.kt` and the emit passes in
`render/Renderer.kt`. Written after §29–§31 of `render-backlog.md`, where five separate bugs all
turned out to be the same two design decisions.

## What's actually wrong

Two decisions in `Fragment`/`TargetLine`, and everything else follows from them.

**1. A fragment splits into `code` and `note`, and `TargetLine.render()` emits every fragment's code
before any fragment's note.** That rule exists so a `//` can never comment out a following fragment's
code. It is correct given trailing comments, and it caused:

| symptom | mechanism |
| --- | --- |
| inlined-region markers detached from their braces | code-then-notes ordering strips each marker off its brace and piles them at the end |
| crammed rows at column 0 | indent is `min` over fragments, so a trailing `}` at depth 0 drags the row to the margin |
| `// L 53 (global) // L 53 (global)` tails | N notes concatenate with no way to say "this one belongs to that code" |

**2. `TargetLine` conflates "belongs to source line N" with "renders as one row",** and flattens by
string concatenation. Placement can't say "this needs two rows"; it can only add fragments and hope.

And on top of both: **passes emit first and reconcile afterwards.** `applyDecompilation` retroactively
sweeps rows it wants, evicting or demoting what earlier passes wrote. That sweep is where §29(a) came
from (`DECOMP`/`STRAY` fell through to the demote branch and compounded to 308,384 chars on
`algparam.h` L113), and it is the *entire* reason `// stray:` exists.

## Front-positioned provenance

`/* L69 */ int test = 1;` instead of `int test = 1;  // ⇐ L 69`. This removes the layer rather than
fixing it:

- The code/note split collapses. An annotation is a block comment in the row's text, at the position
  it belongs to. `commentFor`, `lineRef`, and the `stale` marker plumbing mostly go.
- `TargetLine`'s ordering rule has nothing left to protect, so the flattening goes with it.
- Every row is valid C by construction — which is what §29(f)'s brace-balance work was reaching for.
- Rows align in a column, because `/* Lnnn */` is fixed width. The `min`-indent hack goes.

**Multiple fragments on one row:** one `/* L n */` per distinct `n`, at the point the content for that
line starts. Same `n` for the whole row → one marker at the front.

```
/* L 53 */ char const[9] _ZTS7XVImage = "7XVImage";  char const[7] _ZTS5Image = "5Image";
/* L 41 */ i._M_node = (_List_iterator_base)c;  /* L 42 */ while( true ) {
```

**Open:** skeleton mode's tags aren't provenance, they're *roles* — `(param)`, `(stack local)`,
`(.bss static)`, `stale N_SOL?`, `@ 0x401000: main`. Those describe a declaration rather than saying
where a statement came from, and reading `/* (param) */ int x;` is worse than the trailing form.
Proposal: front-position is for **line provenance only**; role annotations stay trailing, and skeleton
mode is the renderer that uses them. That keeps rule 1's hazard alive in skeleton mode only, where a
row is a single declaration and there is nothing after it to swallow.

## Claim and resolve

Replace *emit-then-reconcile* with *claim, then allocate once*.

```kotlin
/** What a pass wants on the canvas. Nothing is written until every claim is in. */
data class Claim(
    val line: Int?,          // anchor; null = floats within its band
    val rows: List<Row>,     // content
    val elastic: Boolean,    // may expand into free rows below (array initializer, struct body)
    val owner: Owner,        // FUNCTION_BODY, GLOBAL, TYPE_BODY, TYPEDEF, INCLUDE
)
```

Phase 1, every pass produces claims and writes nothing. Phase 2, one allocator assigns rows.
Contention is resolved with the full picture, so there is never a need to go back and evict.

**Pass order.** Your proposal — functions, then globals/statics, then type declarations, then typedefs,
with includes in the space before the first attested line — is right, but I think for a reason worth
being explicit about, because it splits into two axes that disagree:

- *Importance*: functions first. In decomp mode they are what the reader came for and they dominate
  the file.
- *Rigidity*: most-constrained-first is the standard way to avoid painting yourself into a corner. By
  that axis, typedefs — exactly one row, at exactly one line — should go **early**, not last, and
  elastic content (array initializers, struct bodies) should go late so it fills what's left.

These conflict on typedefs. Suggested resolution: **order passes by importance, allocate within the
whole set by rigidity.** Concretely, priority decides who *wins a contested row*; the allocator still
places rigid single-row claims before letting an elastic claim expand over them. A typedef then keeps
its line unless a function body genuinely needs that exact row, which is the behaviour we want and
neither axis gives alone.

Elastic claims are the interesting case and match your description: a big array's start line is
attested, its extent is not. It claims `line` plus "as many rows below as are free before the next
claim", which is `layoutBraceBlock`'s existing behaviour generalised and made explicit instead of
being a special case inside one emit pass.

Includes get the band before the first attested line — already true, now stated as a claim over a
region rather than a pass that reaches for `canvas[1..firstContent]`.

## Strays: the proof obligation

Measured on the current `unpackfile.exe` render — **183 stray fragments**, and none of them are
irrelevant:

```
  9  // stray: };
  4  // stray: public:
  3  // stray: typedef __true_type __Normal;
  2  // stray: class iterator_traits<Exclusion*>;
  1  // stray: _Words _M_word_zero;
```

They are type-body rows (`};`, `public:`, members) and typedefs whose rows fell inside a function's
span. That is *contention*, not noise: a `TYPE_BODY` claim and a `FUNCTION_BODY` claim wanted the same
rows, and today the answer is "whoever wrote first, then the sweep demotes the loser to a comment".

So `// stray:` doesn't go away because the content is worthless. It goes away because under
claim-and-resolve there is no losing-fragment dumping ground: a claim is either **placed** (the
allocator found it a row) or **dropped with a recorded reason** (misattributed — §17's libstdc++
typedefs at .cpp line numbers, §27's stale N_SOL), which is a diagnostic counter, not output.

**Ship gate:** the rewrite is only correct if every one of those 183 lands in one of those two
buckets. The check is mechanical — count claims in, placed + dropped out, assert no third category —
and it should be a test, not a one-off.

## Rough shape of the work

1. `Row`/`Claim`/`Owner` + the allocator, pure, unit-testable in `LayoutTest` (Kind 1). **DONE**
2. Port the emit passes to return claims instead of writing to a canvas. **typedefs, params/locals
   and globals DONE** — verified byte-identical (typedefs, globals) or reorder-only (locals: a
   misattributed decl now renders *after* the real one on its line, since stale claims reserve last).

   **`emitTypeBodies` DONE**, once the case it exposed was understood. Two type bodies at one
   declLine are usually not two declarations at all: every instantiation of a template carries the
   *template's* line, so N of them arrive for a line the source declares once. Letting them contend
   produced a class that does not exist — `unpackfile.cpp` L571 had the `const` instantiation's
   opener above the non-`const` one's member. They are now merged: the fullest body renders, tagged
   `/* 4 bytes, 2 instantiations */`, chosen by member count then name so the pick cannot drift.

   Genuinely distinct elastic claims on one line keep the tiebreak we agreed — **the fullest
   expands**, the rest fold losslessly onto the row it took — with text as a stable secondary key.
   Applied to elastic claims only, so rigid ordering is untouched.

   *Content change, deliberate:* the merged instantiations' bodies no longer appear. They were
   present before, folded onto the shared row as an unreadable tail — `image.h` L571 was 573 chars
   holding both, now 241 holding one. Skeleton p95 row 351 → 308. **DONE:** they get an
   appendix, one line each with their declLine, the way `anonAggregateAppendix` handles anonymous
   types — including base clauses, which is where instantiations differ most visibly and which the
   first cut dropped. Against the pre-rewrite render no code is lost now; the only residue is
   duplicate `// L nnn` tags collapsing to one, which is the merge working.

3. **Allocator needs a placement policy first — DONE.** Porting the decomp path revealed the
   allocator was missing a dimension. A declaration wants its line *or nothing*; a decompiled
   statement wants *the next free row* when its line is taken, because Ghidra revisits a source line
   — 47 of 186 anchors in `xvimage.cpp` are claimed twice — and the second visit is real code.
   Treating those as peers would cram 47 pairs onto single rows. `Anchoring { EXACT, AFTER, BAND }`
   makes it explicit; `AFTER` also covers a claim with no line of its own, which follows the cursor
   rather than floating to the header band (an inlined-region marker riding its call site).

4. Port `applyDecompilation` — **attempted twice, backed out twice.** The port itself is ~30 lines
   and reverts cleanly; what it keeps exposing is that the decomp path needs semantics the
   declaration passes don't. Three were found and are now in the allocator:

   - **`Anchoring.AFTER` never fails.** When the window is full it crams onto the last usable row
     rather than returning `NO_ROOM`. Dropping is right for a declaration — one placed two rows from
     its line is a lie — and wrong for code, which exists and has to go somewhere.
   - **Only `EXACT` claims merge.** Identical declarations at one line are the same declaration seen
     twice, which is where the `×N` counts come from. Identical *statements* are two executions of
     the same code, and collapsing them loses it.
   - **A shared placement must record the row it resolved to**, not re-read `claim.line`. Crammed
     `AFTER` claims were landing back on the anchor they had already slid away from.

   With all three, the port still loses **2,984 tokens corpus-wide against 57 gained** — verified as
   real loss, not redistribution between files, by totalling token multisets across all 55 outputs.
   The residue is concentrated in `L`/address tags and in `std`/`Exclusion`/`allocator` identifiers,
   i.e. whole inlined-region rows from the second pass.

   **Do not retry by eyeball.** The next attempt wants a differential harness: render both paths in
   one process and assert row-for-row that every `DecompLine` handed to `place` appears in the
   output. Three rounds of diffing whole files has each time found *a* real bug and each time missed
   the rest.

5. Two renderers over the same claims: decomp (front provenance) and skeleton (trailing roles).
6. Delete `FragmentKind.STRAY`, `commentFor`'s stray/decomp cases, and the sweep.

Steps 1–3 are behaviour-preserving and independently verifiable against the current renders; the
output should not move until step 5.

## Settled

1. **Skeleton role annotations stay trailing.** Front-position is for line provenance only.
2. **A dropped claim leaves a trace in the file** — a single line at the point of loss naming what and
   why (`/* 3 declarations not shown: misattributed */`) — behind an option to suppress it. The
   diagnostic counter is kept either way.
3. **Identical claims merge in the allocator, carrying multiplicity.** The `×N` inlined-copy dedup is
   a special case of a general rule: two claims for the same line with the same rows *are* the same
   claim. Stating it once in the allocator subsumes both the `groupBy` in the second decomp pass and
   `RenderContext.seenDecls`/`dedup(line, name)`, which hand-rolls the same idea keyed on
   `(line, name)` instead of on content.

   Note the behaviour change that falls out: `dedup(line, name)` currently keeps the *first*
   declaration of a name on a line and silently drops the rest, including ones whose content differs.
   Under content-merge those are no longer duplicates — they are two claims contending for a row,
   resolved by priority, and the loser is dropped *with a reason* and traced. More honest, and it
   surfaces collisions that are currently invisible.

## Allocator model

Separation of concerns the session kept violating: **the allocator assigns space, the renderer fits
content into it.** Cramming, wrapping and spreading are the renderer's business — the allocator only
answers "which rows does this claim get".

```kotlin
enum class Fit { RIGID, ELASTIC }        // exactly its rows, or its rows then whatever is free below
enum class Owner { FUNCTION_BODY, GLOBAL, TYPE_BODY, TYPEDEF, INCLUDE }   // declaration order = priority

data class Row(val text: String, val indent: Int = 0)
data class Claim(val owner: Owner, val line: Int?, val rows: List<Row>, val fit: Fit = Fit.RIGID)

data class Placement(val claim: Claim, val range: IntRange, val copies: Int = 1)
data class Dropped(val claim: Claim, val reason: String)
data class Allocation(val placed: List<Placement>, val dropped: List<Dropped>)
```

Resolution order, per the two axes above: identical claims merge first; then **rigidity** (`RIGID`
before `ELASTIC`, so a one-row typedef takes its line before an array initializer expands over it);
then **priority** (`Owner` ordinal, so a function body wins a genuinely contested row); then line.

A claim with `line == null` floats in the band before the first anchored row — that is `INCLUDE`.
