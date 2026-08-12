# Source root: ground truth from the sources the binary was built from

Draft, 2026-08-12. Adds an optional `--source-root` (and analyzer option) pointing at the sources a
binary was compiled from, and uses it as ground truth in four places. Written after §44 of
`render-backlog.md`, which measured what the render currently gets right by checking unpackfile
against libstdc++ 3.2.3 itself.

## Why

Everything the render says about *where* something came from is gcc's word, and §38 established that
gcc drops the file of any deferred declaration. The render has been compensating with heuristics —
`multiSourceHeaderHints`' vote, `conflictedTemplateDecls`, `activityExtent`, §43's proposed gap rule —
each of which is an inference from the debug info about the debug info. When the sources are on disk,
most of those questions stop being inferences.

§44's numbers, on unpackfile against `releases/gcc-3.2.3`:

| | |
| --- | --- |
| inlined stretches naming a libstdc++ file | 392 occurrences, **100% land on real code**, 94% inside a function whose name the source gives |
| declarations with libstdc++ ground truth | 185: **63% right line**, 5% right file/wrong line, 29% filed under the wrong file, 2% past EOF |
| misfiled declarations | 48 distinct, **24 declared at the very same line in another file** |

Two facts follow, and they are the whole design. **The line is usually right and the file is usually
wrong** — so a source root does not need to correct positions, it needs to *identify files*. And
**a file's real length is knowable**, which is the one input §43's circular extent problem lacks.

## What it is used for

Four uses, in dependency order. Each reuses one index; none of them changes behaviour when no root is
given.

1. **Name the inlined stretches.** `__inline_stl_vector_h_123` → `_M_deallocate`, and
   `Region.definitionHead` can carry the source's real signature and parameter names instead of the
   callee's frame-slot guesses. Cheapest reader-visible win: 94% of stretches resolve.
2. **Re-attribute misfiled declarations.** Search the root for a file declaring `(name, line)`;
   `_Is_POD` claimed at basic_string.h:111 is stl_uninitialized.h:**111**. Attacks the §38/§43 family
   at the root instead of one symptom at a time.
3. **A real file length.** For an included file, `activityExtent`/`ownExtent` become `wc -l`. §43's
   residue — a header measured by the declarations it is judging, so one uncorroborated declaration
   vouches for itself — disappears, with no gap statistic to tune.
4. **An attribution scorecard.** §44 as counters, so attribution regressions are caught the way row
   counts catch layout ones. Today an attribution change can only be graded by hand, which is how item
   9 shipped with a silent content loss that only a second fixture exposed.

## What Ghidra already provides, and what it does not

Both cparser packages were read before choosing, because the obvious move — "Ghidra has a C parser,
point it at the headers" — does not survive contact.

**`ghidra.app.util.cparser.C` — cannot do this job.** The complete keyword token list in `C.jj` is
`auto break case char continue default do double else enum extern float for goto if int long register
return short sizeof static struct switch typedef union unsigned void while` plus
`__attribute/__declspec/__far/__near/__packed/__unaligned`. No `class`, `template`, `namespace`,
`operator`, `::` — a C grammar with MSVC/GCC extensions and some ObjC. `<bits/stl_vector.h>` is out of
reach entirely. It *does* track provenance internally (`headerFileName`/`headerFileLine`/
`headerFileLineOffset`, `C.jj:123-125`, fed by `LineDef()` at `C.jj:1525`), but only to format parse
messages; the only provenance that reaches a result is the *file*, as the DataType's category. It
parses function definitions (`C.jj:1547`) and exposes them by name (`C.jj:878`) — with no line. So it
can never answer "what is at stl_vector.h:123".

**`ghidra.app.util.cparser.CPP.PreProcessor` — genuinely useful, and it changes the design.** It has
no grammar to choke on, so C++ passes through untouched, and it gives three things:

- **Compiler-faithful include resolution.** `addIncludePaths(String[])`, then `includeFile`
  (`CPP.jj:883-935`) walks the `-I` list and falls back to the including file's own directory,
  warning `No path to #include X … Use -I option`. This is §44's mapping problem — `<iostream>` is
  `include/std/std_iostream.h`, `atomicity.h` is `config/cpu/i486/bits/atomicity.h`, `basic_file.h` is
  `config/io/basic_file_stdio.h` — answered by resolution rather than by guessing at path suffixes.
- **A `#line`-tagged stream.** It emits `#line <n>: "<file>"` at every file switch (`CPP.jj:1635-1684`),
  so preprocessed text carries (file, line) throughout — **and contains only the branches that were
  actually compiled**. libstdc++ is dense with `#ifdef _GLIBCPP_…` and per-OS branches; scanning raw
  text indexes code the compiler never saw. This is the strongest argument for it.
- **Macros with provenance.** `DefineTable.getDefineNames/getValue/isNumeric/getDefinitionPath`
  (`DefineTable.java:230-265`) and `populateDefineEquates` — numeric `#define`s straight into Ghidra's
  equate table, filed per file. Not in this plan's scope; noted because it is nearly free later and
  sits next to the existing stabs `:c=`-constants-as-equates work.

**The catch that decides the architecture:** preprocessing libstdc++ needs the whole include
environment, and `bits/c++config.h` is *generated at build time* — it is not in a source tarball. Point
a root at pristine gcc and includes will not resolve. So the preprocessor is an **input strategy**,
not a dependency:

```
                     ┌─ PreProcessor (roots as -I) ──→ #line-tagged text ─┐
render spelling ──→  │                                                     ├─→ scanner ─→ index
                     └─ raw file (suffix-resolved) ───────────────────────┘
```

Same scanner either way; only the text differs, and the fallback is what §44 measured at 94%.

## Architecture

New package `ghistabs/source/`, with no dependency on `render/` or `harvest/` — it answers questions
about text, and callers decide what to do with the answers.

```kotlin
/** A definition the source carries, with the brace extent gcc compiled from it. */
data class Definition(val name: String, val start: Int, val end: Int)

/** Pure: every function-like definition in one file's text, by brace matching. */
fun definitionsIn(text: CharSequence): List<Definition>

/** Pure: declared name → the lines that declare it (class/struct/union/enum/typedef). */
fun declarationsIn(text: CharSequence): Map<String, List<Int>>

class SourceIndex(roots: List<File>, sink: DiagnosticSink) {
    fun enclosing(spelling: String, line: Int): Definition?   // use 1
    fun declarers(name: String, line: Int): List<String>      // use 2
    fun lineCount(spelling: String): Int?                     // use 3
    fun agreement(spelling: String): Double?                  // the mismatch guard
}
```

The scanner strips comments and string literals first (a small state machine that preserves line
breaks), then matches braces, because a brace inside `"}"` or a comment otherwise ends a body early.
It records every `{` whose head contains a `(` at template depth 0, so methods inside class bodies are
found as well as free functions — that is where most of libstdc++ lives.

**Resolution** takes the render's *full* spelling (`c:/mingw/include/c++/3.2.3/bits/stl_vector.h`),
not the basename the marker displays, and tries, in order: the preprocessor's resolved map; longest
matching path suffix; unique basename. Ambiguity is never broken by guessing — it logs
`source-file-ambiguous` and yields nothing, because a wrong file produces confidently wrong names,
which is worse than the `__inline_…` fallback it replaces.

**Version guard.** A root for the wrong version is the failure mode that produces plausible lies. Per
file, `agreement` = the fraction of that file's attributed declaration names that appear within ±2 of
their claimed line. Below a floor (start at 0.5, measured before fixing), the file is dropped with
`source-root-mismatch` naming it, and everything falls back to today's behaviour. Corpus evidence for
the floor: unpackfile's *correctly* attributed libstdc++ files score 63% with the pristine tree, so
the floor has to sit below that and the guard is per file, not per root.

**Wiring.** `StabsOptions.sourceRoots: List<File>` (empty = off), from a repeatable `--source-root` on
both CLI commands and a path-list analyzer option. The index is built once and hung on `HarvestIndex`,
because uses 2 and 3 are attribution questions the *importer* asks and uses 1 and 4 are render
questions — one owner, one cache, and the analyzer path gets re-attribution for free.

## Decisions, and what was rejected

- **Not CParser for naming.** C-only; cannot see a line. Its slot is a later, opt-in pass over a *C*
  project's headers for the `/* 0 bytes */` opaque types, never libstdc++.
- **Not "trust the source over the stabs".** The source root corrects *files*, never lines: §44 shows
  the line is right 63% of the time and, where it is wrong, the source cannot say what gcc meant.
- **Not a fuzzy match.** No nearest-name, no edit distance. Either a file declares that name at that
  line or it does not; ambiguity is reported, not resolved.
- **Not on by default.** No root, no behaviour change — every measurement in the backlog stays
  comparable, and the fixtures keep working without a gcc checkout.

## Open questions

- **Cost.** Preprocessing libstdc++ per run is not free. Expect to cache the scan per (file, mtime) in
  memory for the run; if it is worse than ~2s on unpackfile, make the preprocessor strategy opt-in
  (`--source-root-preprocess`) and default to raw scanning.
- **Which name to render.** `_M_deallocate__stl_vector_h_123` keeps §36's property that the .cpp's call
  and the header's definition compute the same string, and stays unique when one file inlines two
  stretches of one function. The shorter `_M_deallocate` reads better but collides. Phase 4 renders the
  long form and the decision gets made against real output.
- **Templates.** A definition's name in the source is `vector<_Tp, _Alloc>::_M_insert_aux`; the render
  knows the *instantiated* type. Phase 4 uses the source's spelling as-is rather than trying to
  substitute — matching gcc's own template argument names is a separate problem.
