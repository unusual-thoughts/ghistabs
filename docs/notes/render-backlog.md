# Source-skeleton / decompilation render backlog

Open rendering issues in `render/`, captured from output review. Fixtures
regenerate under `build/test-output/{skeletons,decomps}/<binary>/`.

## Status audit, 2026-08-25

Every open item re-checked against the code and against the 24 regenerated baselines
(`src/test/resources/baselines/`, 2026-08-24 — 160 counters across the whole corpus). Four items
had been fixed without the note being updated (§24's Level B, §40's silent fallback, §23's vbase
prefix, §32's stray sweep); four were confirmed open by reading the code that would have had to
change and hadn't (§25, §26, §30's `this`, §37(d)); §36 was downgraded to needs-re-measure, and
§41 was reframed from one red fixture to a corpus-wide number.

**A baseline counter is a range, not a value.** Each carries `min`/`max` across run modes, mostly
equal but hand-widened where a mode genuinely differs — 46 entries across the corpus are widened.
So a *total* summed over fixtures inherits that slack (`demangler-unbound-stub` is 840–841), while
a single fixture's figure is usually exact. Every per-fixture number quoted in this file's
2026-08-25 additions was checked to be a point snapshot; the totals are given as ranges where they
are not.

### Every section, classified

**§1–§52, no gaps, no duplicates** — after renumbering the second §39 (see §52). Plus four
unnumbered sections. Sections are numbered in the order they were *found*, so the numbering carries
no meaning beyond identity; this is the whole set, and nothing below is unclassified.

**Open or partial — 12.** §23 (MI/VTT half), §24 (vtable `rtti` link + Level A), §25 (plus the
`ztvCandidates` shorthand gap found under it), §26, §30 (the missing `this`), §32 (the model swap),
§36 (needs re-measure), §37 (d/f/g), §38, §40 (the 30 s budget), §41, §44 (measurement).
Unnumbered: **`4900866`** (open question, now baseline-pinned) and **Render output is not parseable
C++** (groups 2–3).

**Done or closed — 40**, i.e. §1–§22 except §13's stale write-up (fixed here), §27–§29, §31,
§33–§35, §39, §42, §43, §45–§52. Unnumbered: **Misattributed declarations** (DONE) and **Class
attribution: `class Image`** (SUPERSEDED by priority 2).

Three carry a header that no longer matches their body and were corrected in this pass rather than
reclassified: §13 (DONE, but its ABI premise and mechanism were wrong), §23 and §24 (were headed
"open", were partly done), §32 and §40 (were headed "open"/"not started", were partly done).

**Check an item against the baselines before reading output.** `rtti-pseudo-substituted`,
`demangler-unbound-stub`, `vtable-failed-truly-missing`, `degraded-param-unnamed-padded`,
`empty-scope` and `reglocal-renamed-scope` each settle a question this file used to ask of one
fixture's render. Where an item has *no* counter — §26 is the case — that absence is the finding:
nothing would detect the defect if a fixture grew one.

`render/` has had one commit since the previous pass, so anything settleable only by regenerating
output (§36's two-sided arity, §37(d)/(f), the grammar totals) is marked *needs re-measure* below
rather than verified-open.

## Priorities

Ranked by what a reader of the output gets per unit of work, as of the grammar pass. Sections are
numbered in the order they were *found*, not worked; this is the order to work them.

**Four that a reader hits immediately.**

1. ~~**§37(a), aliased copies render two and three times.**~~ — DONE, see §37(a).
2. **image.h: 25 rows of its own, 31 of libstdc++, spread over 908 lines.** — MOSTLY DONE, see below. Measured after the §38
   and §39 work, and the diagnosis in the old note was wrong twice, so read this before starting.
   - **It is not `declSourceFile`.** `effectiveSource` consults that only for non-Struct/Enum
     bodies; every one of these is a `class`, so they arrive via `id.source.filename` — the BINCL
     block gcc happened to instantiate the template in. `vector<short unsigned int>` really was
     emitted inside image.h's block, so the stab is not lying, it is just not what a reader wants.
   - **It is not the extent circularity either**, and a code-extent rule cannot fix it: image.h has
     **no N_SLINE entries at all** (nor do xdvimage.h or bits64image.h). There is no code evidence
     to measure it by.
   - **The stated blocker for the headers that *do* have code is now stale.** The note said measuring
     xvimage.h by code "stopped at 32 and called `class XVImage` at 36 misattributed" — that was the
     *unfolded* spelling. §39 folds onto the full path, whose bucket reaches **39**, so its own class
     is inside. Same for appimage.h (35, class at 19), vminfo.h (83), filesystemimage.h (117). A code
     extent now works for that half; only the no-code headers need something else.
   - **The evidence exists and `multiSourceHeaderHints` is the right mechanism — two guards stop it.**
     `vector<unsigned short>` does have one out-of-line method, `_M_fill_insert` (easy to miss: the
     stabs spell the type `vector<short unsigned int,…>` and the render `vector<unsigned_short,…>`),
     and the header line-entries inside its address range are stl_vector.h, stl_algobase.h,
     stl_uninitialized.h, stl_alloc.h and stl_iterator.h — all stdlib, which is the answer wanted.
     What blocks it:
     1. `if (defSources.all { it.hasHeaderExtension() }) continue` — the type is declared only in
        image.h, which *is* a header, so the vote never runs. Being in *a* header is not being in the
        *right* one.
     2. `stdVote.takeIf { defSources.size > 1 }` — with one defSource the stdlib branch is off too,
        so relaxing (1) alone changes nothing.
     Guard (2) protects a real case, recorded in its own comment: `class Image` is stabs-declared in
     stl_vector.h and must stay in image.h. But that case is already held by the ranking —
     `userVote ?: siblingHeader ?: stdVote` — because Image's methods live in user files and vote
     user, while `vector<…>`'s live in stdlib ones and vote std. Check that before deleting it.

     **Remaining unknown, and the only one:** whether the vote lands on stl_vector.h or on
     stl_algobase.h, since `_M_fill_insert`'s range covers inlined stretches of both. If it picks the
     wrong sibling the answer is still a stdlib header rather than a project one, which is most of the
     win; count the entries before deciding whether it needs a tie-break.

     **Done, both guards.** A *template instantiation* now skips guard (1) — gcc files those by
     accident, everything else declared only in headers is left alone, which also bounds the loop —
     and for one, `stdVote` outranks `siblingHeader`: an instantiation follows its code, while its
     sibling header is just the CU that happened to need it. A plain class keeps the old ranking, so
     `class Image` stays in image.h. A second pass propagates a template's home to instantiations with
     no method evidence of their own (`_Vector_alloc_base<unsigned short>` declares three pointers and
     no methods, so `_Vector_alloc_base<Exclusion>` answers for it).

     appquery: image.h 56 → 41 rows, xvimage.h 75 → 66, vminfo.h 74 → 57, filesystemimage.h 60 → 46,
     with stl_vector.h +8, stl_tree.h +12, stl_alloc.h +6, stl_iterator.h +6, stl_list.h +4.
     unpackfile the same shape. All four project classes stay in their own headers. Totals fall 19
     rows because instantiations arriving at a header that already renders one merge into it and are
     listed in the instantiation appendix; render time is unchanged.

     **Base classes follow their derived class — done.** `_Vector_alloc_base<unsigned short>` has no
     methods and no instantiation of that template anywhere has an out-of-line one, so neither the
     vote nor the sibling pass could reach it; what *is* known is that `_Vector_base<unsigned short>`,
     which derives from it, went to stl_vector.h. Three rounds, templates only, so a project class
     cannot be dragged along by a base it shares with the standard library. image.h 41 → 35 rows,
     xvimage.h 66 → 60, vminfo.h 57 → 52 — every row that moved was a `_Vector_alloc_base<…>`, and
     `class Image`, `class XVImage`, `class VmInfo` all stayed. Extending it to *field* types as well
     moved nothing on the corpus, so it stays bases-only.

     **Sibling seeding, done — the pass was only half-seeded.** `homeByTemplate` was built from
     *voted* homes alone, so it could not see the instantiations nothing was ever wrong with:
     `allocator<char>`, `<void>` and `<wchar_t>` sit in stl_alloc.h because gcc put them there, and
     they are exactly what says where `allocator<unsigned short>` belongs. Seeding it from `id.source`
     as well — stdlib homes only, and `id.source` rather than the effective source, since this map is
     what the effective source consults — moves both stragglers out of image.h.

     Corpus-wide it reaches far past image.h: eleven project files shed 46 rows of libstdc++ and seven
     stdlib headers gained 25 (the difference is instantiations merging into a declaration already
     rendered at the destination). image.h **56 → 28 rows** across the whole item, xvimage.h 75 → 53,
     vminfo.h 74 → 49, main.cpp 182 → 176. All six project classes stay in their own headers.

     One honest imprecision: `__normal_iterator<unsigned short*>` lands in **basic_string.tcc**, not
     stl_iterator.h, because basic_string.tcc is the only stdlib file holding a sibling of that
     template in this binary. A stdlib header rather than a project one is most of the win, but it is
     the wrong stdlib header, and nothing in the debug info prefers the right one.

     **The last type could not be named, so it is no longer placed — DONE.** `_Alloc_traits<unsigned
     short>` (image.h L898) has no methods, no base relationship and no instantiation in any stdlib
     header, so nothing can name its home (stl_alloc.h) — §38's grade-3 wall. But every one of its
     eight instantiations carries declLine **898** across image.h, vminfo.h, xvimage.h and three CUs,
     and a template is declared once: they cannot all be right. Knowing they are all wrong is enough
     to stop placing them, which is what the displaced appendix is for.

     `conflictedTemplateDecls` collects `(template, declLine)` pairs filed under more than one source;
     such a declaration renders only where the line is one the file plausibly reaches (`ownExtent` —
     code, globals, and the type declarations not themselves in dispute). stl_vector.h's content runs
     past L900 so it keeps its copy; image.h stops at L53 and cannot be declaring anything at L898.

     **This is where the blank space went.** image.h **903 → 59 lines**, xvimage.h 903 → 79,
     vminfo.h 904 → 196; appquery's whole render 24,957 → 22,581 lines with row count unchanged
     (3121 → 3122, the appendix entries). Nothing else in the render moves. §33's numbers can now be
     re-measured honestly — and a good part of what they were counting was this.

   **§38 is the third instance of the extent circularity and the worst**: `main.cpp` rendered 1456
   rows for a 166-line file. That half is DONE; the exact RTTI attribution (§38 grade 1) is too.
3. ~~**§33, blank space.**~~ — DONE. Compact by default (18,194 rows → 3,128 on unpackfile),
   `--line-aligned` for the old output.
4. **`redefinition of X`** — partly done, and it is three different things, not one.
   - **~15 `numeric_limits` in `<limits>`** — one template instantiated per arithmetic type, every
     copy rendered under the shortened name. The instantiation merge that handles this elsewhere is
     not reaching them.
   - **~40 `__inline_…` pseudo-functions.** A header line inlined into several callers is wrapped as
     a definition per caller. Two fixes apply: identical text at one anchor is now merged whatever
     inlined it (the `×N` the design already intended — keying on the inliner defeated it, worth 11
     rows and 10 clang errors), and where the *text* differs the definitions are usually legal
     overloads, because a template inlined at different element types takes different parameters.
     What is left is the case in between: same anchor, same signature, bodies differing only in the
     local names Ghidra assigns per call site. Merging those means keeping the fullest and tagging
     `×N` — the answer `typeBodyClaims` already gives for N instantiations at one declaration site —
     and it does discard a body, so it wants a look at how different they really are first.
   - **~12 locals in stl_tree.h** (`__x`, `__y`, `__root` redeclared, sometimes at a different type).
     Statements at file scope in a header view, i.e. the design gap in group 2 of the grammar
     section, not a dedup bug.

**Then — structural correctness that the counters do not fully see.**

5. ~~**Brace nesting.**~~ — DONE, see §34.
6. ~~**§37(b)+(c), claims cross function boundaries.**~~ — DONE, see §37(b)/(c).
7. **§37(d), member calls still pass `this`.** `find_slt(this,…)` ×5 while the definition it calls has
   had the parameter stripped, so the two halves of the render contradict each other. Mechanical, and
   the same token knowledge `renameThis` already uses — the grammar section's `'this' is a keyword`
   family fixed only the definition side. **Verified still open (2026-08-25):** `renameThis` is
   applied in exactly one place, `wrapAsDefinition` (`Region.kt:303`), which is the definition side;
   no call site consults it.
8. ~~**8 markers still outside their block.**~~ — DONE, see §42.
9. ~~**`activityExtent`'s header proxy.**~~ — DONE, see §43 and §47. The regime is gcc's `N_SO` now,
   and where a source root maps the file its extent is the file's own length rather than an estimate
   built from the declarations it judges. What is left is the no-root path and the files no root
   maps: there a header is still measured by its own declarations, so one uncorroborated declaration
   vouches for itself, and §43 records what an outlier rule has to do.

**Structural debt, worth taking before more of the above.**

10. ~~**§35, stop reconstructing what the token tree knows.**~~ — DONE. What is left there is one
    diagnostic and a note that the item's premise about `toLines` was wrong.

**Lower — measurement, then long-standing limitations.**

11. **Forward-declare referenced templates.** Would make the error total mean something again (an
    undeclared template manufactures syntax errors), but arity varies per instantiation because of
    default arguments, so the declaration is not straightforwardly derivable.
12. **§37(g), resolve the vtable-slot call.** `(**(code **)(*(int *)this + 8))(…)` is an offset into a
    vtable whose type the render declares in the same file, so it can be spelled as the method it
    calls. Small, and it reads as a real call rather than arithmetic. Nothing in `render/` reads a
    vtable slot today, so this is still all of the work it was.
13. **§37(f), the displaced/stale tail.** 19 rows on a ~150-line file, four claiming lines 302–348.
    The `stale N_SOL` ones are the activity extent already saying they do not belong; this is the
    "Misattributed declarations" work applied to the trailing block rather than to placement.
14. §23 multi-vtable ABI, §24 RTTI wiring, §25 unannotated `_ZTV`, §26 bitfields, §30 unnamed
    parameters, §21 leftovers, and the `4900866` a.out neutrality question. All pre-date this pass and
    none block a reader of the render.

### Re-ranked open set, 2026-08-25

The list above is kept as the record of what was worked in what order. This is what is actually
left, ranked after the audit. Rows 1–3 are the ones a reader or a maintainer hits; 4–6 are real
defects with no reader visible yet; the rest are bounded work with a known shape.

| #  | Item                                                              | Why here                                                                                                                                                                                                                                                                                                                                                                                      | Size                                                |
|----|-------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------|
| 1  | **§26 bitfields**                                                 | The only item that *silently destroys data* — `replaceAtOffset(offsetBits/8)` makes the second bitfield overwrite the first, and no counter anywhere would report it. Verify a fixture has one first.                                                                                                                                                                                         | small once a fixture is found                       |
| 2  | **§37(d) `this` at call sites**                                   | Cheapest reader-visible contradiction left; one lookup away from code that already exists.                                                                                                                                                                                                                                                                                                    | small                                               |
| 3  | **§41 triage the unbound stubs**                                  | Now a corpus-wide number (840–841 across 19 fixtures) rather than one red fixture; until it is triaged nobody knows whether it is inherent or a materialization gap.                                                                                                                                                                                                                          | a reading pass                                      |
| 4  | **§30 the missing `this`**                                        | 248/542 cryptopp methods *as measured then, on a smaller corpus and never re-checked*; padding is in and working corpus-wide (5468 across 20 fixtures) but the origin is untouched and has *no counter* — instrument it as the first step, which also re-establishes the 248.                                                                                                                 | medium, suspect named                               |
| 5  | **§36 re-measure, then unify the key**                            | The disagreement table predates the source-root work; re-measure before committing to a `regionsOf` change.                                                                                                                                                                                                                                                                                   | measure, then medium                                |
| 6  | **§24 remainder**                                                 | Level B shipped; what is left is pointing the vtable `rtti` field at the typeinfo struct (one line's worth of wiring against `Vtable.kt`'s own TODO) plus Level A, which the corpus barely needs.                                                                                                                                                                                             | small                                               |
| 7  | **§40 remainder**                                                 | The silent half is fixed — a timeout now renders. Left: whether 30 s is the right budget, i.e. reproducibility itself.                                                                                                                                                                                                                                                                        | small                                               |
| 8  | **§25 — but first, restore the STL shorthand to `ztvCandidates`** | `vtable-failed-truly-missing` = 400 across 6 fixtures, ~10× worse on the stripped twins (crypto_mi_test_gcc421_fullstabs 10 → its `_stripped` twin 121). Diagnosed: the closed-form candidate builder can spell neither `Ss`/`Sa`/`Si`/`So`/`Sd`/`St` shorthand nor any template, and the symbol index that covered for it is what a strip deletes. Most of the 400 is that, not §25's sweep. | **small** for the shorthand; medium for what's left |
| 9  | **§32 the rest of the layout rewrite**                            | Claim-and-resolve landed; front-positioned provenance and retiring `Fragment`/`TargetLine` did not. Pure debt.                                                                                                                                                                                                                                                                                | large                                               |
| 10 | **§38, §37(f), prio-4 `redefinition of X`, grammar groups 2–3**   | All need output regenerated before they can be re-stated honestly.                                                                                                                                                                                                                                                                                                                            | measure first                                       |
| 11 | **§23 residual, §44, `4900866`**                                  | Limitations and open questions, none blocking a reader. `4900866` has the sharpest edge: the disputed behaviour is now *pinned by a baseline* while which block tree is correct was never established.                                                                                                                                                                                        | —                                                   |

### The non-render half, ranked on its own

The table above mixes two kinds of work. Everything that lands in the *program* — types, vtables,
signatures, symbols — is worth its own ordering, because it is what every consumer sees whether or
not a skeleton is ever rendered, and because none of it needs output regenerated to work on.

| # | Item                                                  | Evidence                                                                                          | Size                        |
|---|-------------------------------------------------------|---------------------------------------------------------------------------------------------------|-----------------------------|
| 1 | **STL shorthand in `ztvCandidates`** (§25 front half) | `vtable-failed-truly-missing` 400/6 fixtures; cause diagnosed, not inferred                       | small                       |
| 2 | **§26 bitfields**                                     | no counter exists; second bitfield overwrites the first                                           | small once a fixture exists |
| 3 | **§21 conflict drift**                                | `dtm-conflicts-created` 0 → 30/13 fixtures against an explicit "zero" claim; names already dumped | a read                      |
| 4 | **§30 the missing `this`**                            | 248/542 then, uncounted now — instrument first                                                    | medium                      |
| 5 | **§41 unbound stub triage**                           | 840–841/19 fixtures; fullstabs-vs-stripped pairs separate inherent from gap                       | a reading pass              |
| 6 | **§24 vtable `rtti` link**                            | Level B live (705 substitutions); the pointee is still `void*`                                    | small                       |
| 7 | **`4900866` a.out block tree**                        | zlib `empty-scope` 24, `reglocal-renamed-scope` 19 — shipped, baselined, never adjudicated        | medium                      |
| 8 | **§53 unstripped static-member miss rate**            | 378 unresolved vs 120 applied *with symbols present*                                              | measure                     |
| 9 | **§23 MI/VTT, §8 N_RSYM liveness**                    | deliberate limitations; no corpus pressure                                                        | —                           |

Rows 1–3 are all small and all sit on stated-zero or unmeasured claims, which is the cheapest kind
of work to be right about. Row 7 is the one that gets worse with time: it is frozen by a baseline.

Row 8 of the main table is mis-ranked by that table's own logic and left in place only to keep the numbering stable:
the `ztvCandidates` shorthand is a **small** change against the largest single counter here (400),
so take it with rows 1–3. The rank stands for the sweep that shares the section, not for the fix.

---

## 1. Single-line functions get no decompiled body — DONE

An inline accessor whose machine code all maps to one source line (e.g.
`AppImage::header_length() const`, all N_SLINEs on L17) was classified as a
single-line `FuncRange` (`isSingleLine`), rendered as a self-closing decl, and
skipped entirely by `applyDecompilation`. Now `applyDecompilation` defaults a
missing close line to the start line, so the whole body crams onto the one decl
line via the existing overflow path. Aliased out-of-line copies (ctor `C1`/`C2`,
dtor `D0`/`D1`/`D2`) collapse onto one line; decompiling each would stack
duplicate bodies, so a single-line function is only bodied when it is the sole
range on its line. Multi-line functions have no such guard and do stack them —
§37(a) — aliases keep the skeleton's side-by-side decls.

## 2. Render decompilation from clang tokens, not flat C text

Rendering now works from the decompiler's **clang token stream** instead of the flat
`.c` string. `render/DecompTokens.kt`: `DecompileResults.tokenLines()` reconstructs each
line's text from its leaf tokens and tags it with the lowest instruction address those
tokens map to — a declaration, brace or comment line has none, a statement line does.
That address is the discriminator the flat text couldn't give.

**Done (leading-decl compression):** `compressedDecompLines()` strips the banner comment,
then folds the signature + `{` + the address-less local-declaration block onto one head
line, so statements start at the top of the span instead of one-decl-per-line pushing
them all down. Same-typed decls are grouped into one statement (`string *a; string *b;` →
`string *a,*b;`) by `groupDecls` — Ghidra spells decl types as a single space-free token,
so the type is the text before the first space and the declarator (with its `*`/`[N]`) the
rest. appquery `names`: ~15 decl lines → one grouped head line. Replaced the text-based
`cleanDecompLines`.

**Done (source-line annotation, option B):** each statement line is tagged `// ⇐ L NN`
with the source line its instructions came from — token address → the function's SLINE
table (`lastOrNull { addr ≤ a }`), foreign source rendered `file.h L NN`. We keep the
decompiler's own statement order and structure rather than *repositioning* to the source
line: Ghidra inverts conditions and leaves gotos/labels, so its C structure isn't the
source's, and repositioning would scatter/collide (verified reasoning). The annotation
gives source correspondence without distorting the layout — `_main` statements tag across
L31→L97, `LAB_…: // ⇐ L 58`, `if (argc < 2) // ⇐ L 51`, a one-source-line loop clusters
on L60. `DecompLine` now carries the address; `commentFor` has a `DECOMP` case.

**Done (coalesce runs, un-cram):** `applyDecompilation` coalesces onto one output line each
run of statements belonging to one this-file source line — repeats of the same line plus
inlined-header code (a foreign N_SOL folds into its call site's line). This cuts the body to
roughly the number of source lines it touches, so it fits the span instead of cramming onto
the close line (appquery `main` close line 8422 → 2909 chars). The folded head (index 0) is
never a fold target. Order and structure stay the decompiler's; each output line keeps its
`// ⇐ L NN` tag.

**Done: dropped the `setMaxWidth(10_000)` stopgap.** No longer needed — the decompiler is free
to wrap long lines, and coalescing re-joins the wrapped continuation lines by address (they
share the statement's source line), so wrapping is transparent. Verified: zero orphan `;`
lines after removal.

**The structural half followed in §35:** the row now carries its braces, its `if`'s condition and
branch extents, its `this`, and where it may be broken — all read from the tokens, which reach us
through `toLines` with their tree parents intact.

## 5. Sweep findings (all fixtures, `--exclude-dir='*.old'`)

Structurally sound: `T_<digits>` dangling type refs = 0; no unparseable garbage.

- **Fixed:** single-line delimiter tags used the raw mangled name while multi-line
  closes used the demangled name; `emitFunctionBraces` now demangles both.
- **Fixed (common case):** orphan `;` from decompiler line-wrapping — harness
  `setMaxWidth(10_000)` (see #2).
- **DONE — [C] raw mangled tags (~212):** closed by §12 (name every function from stabs +
  run the demangle pass). Verified: **no bare ctor/dtor mangled function tags remain** in any
  fixture. The only surviving `_ZN…C2Ev` occurrences are embedded in `_GLOBAL__I_/_GLOBAL__D_`
  static-init/destruction thunk names (e.g. `_GLOBAL__I__ZN8XDVImageC2Ev`) — legitimate GNU
  symbols Ghidra neither can nor should demangle, consistent across skeleton and decomp modes.
- **DONE — [E] orphan punctuation (was ~74 lone `;` / 38 files, decomp):** Ghidra split an extreme
  `std::` member-access chain or long call and broke the trailing `;` onto its own line with no extra
  indent; that fragment carries no address, so the depth-based rejoin couldn't see it. `compressedDecompLines`'
  continuation test now also folds any line whose significant tokens are all trailing punctuation
  (`;`/`)`/`.`/`,`/`->`, braces excluded so `}` keeps its row) onto the preceding statement row.
  Verified: lone-`;`/`.`/`)` across all fixtures **74 → 0**, the `;` re-attaches to its statement
  (`…_M_start ;  // ⇐ stl_iterator.h L 584`), full integration suite green.
- **Keep (not a defect) — stale N_SOL in decomp (~129):** *(§27 removed the locals/params half of this — the markers that remain are addressless types.)* the `// … stale N_SOL?` markers are
  *useful* diagnostics — they flag content (reg-locals/params, misattributed fragments) that needs
  excluding from decomp by some other mechanism, not by silencing the marker. Leave them; the real
  work is acting on what they point at, not trimming the annotation.
- **Not our bug:** `DAT_*`/`PTR_*` in decomp bodies are Ghidra's names for data it
  didn't tie to a symbol (vtable pointers, literals); `<true,0>`/`<false,0>` are
  valid non-type template args; `/* 0 bytes */` are the documented `noEmptyStructs`
  degradation (forward decls / opaque types).

## 3. Map stab frame offsets onto Ghidra's `in_stack_*` decomp vars

Investigated: our line placement is **correct**. In a gcc N_LSYM/N_PSYM stab the
`desc` field is the declaration line (used for `declLine`/placement) and `n_value`
is the EBP-relative frame offset — e.g. `this:(1,151)` → `desc=375` (line),
`value=0xffffff70` (−144). We already ignore `value` for lines. So there is no
line-conflation bug.

The real opportunity: the `undefined2 in_stack_0000000e;` entries are Ghidra's
decompiler naming an *incoming stack parameter at +0xe* it never folded into a
named param. The stab `Param`/`StackLocal` carries the matching frame offset
(`n_value`); matching stab offset → Ghidra decomp storage would let us rename
`in_stack_*` to the real source name. Ties into #2 (token-level decomp cleanup).

**We DO define locals** — `StabsImporter.applyLocal` adds each stack local via
`LocalVariableImpl(name, dt, stackOffset, …)` with `stackOffset =
loc.rawValue.toInt()` (`StabsImporter.kt:467`) and each reg local via the dbx
register. Params go through `ParameterImpl` with `DYNAMIC_STORAGE_FORMAL_PARAMS`,
so Ghidra assigns their storage from the calling convention (stab offset ignored
for params).

**FIXED.** The stack-local offset was passed through raw. gcc's `n_value` is
frame-pointer-relative (saved FP=0, return addr=+ptr, first param=+2·ptr); Ghidra's
`LocalVariableImpl` offset is relative to SP at entry (return addr=0), so they
differ by one pointer (the saved-FP slot) — confirmed by NSA/ghidra#223, #5485 and
by the PSYM values (`this:p=+8`, `argc:p=+8` → Ghidra +4). The bias is not a
hardcoded constant: it's `VariableUtilities.getBaseStackParamOffset` (where the
calling convention starts stack params — the same saved-FP slot), read once
program-wide in `deriveStackFrameBias`. Result: appquery `local_` 1816→1562 as the
decompiler now adopts our named locals.

## 4. `_ZTS*` typeinfo-name globals + function overlap (xdvimage.cpp L131–133) — DONE

Three coupled defects around the RTTI typeinfo-name strings gcc attributes to a
single source line inside `XDVImage::symbol_start`. **Verified fixed across all
fixtures:**

- **Render as string — FIXED.** Every `_ZTS*` global now renders as a quoted literal
  (`char const[10] _ZTS8XDVImage = "8XDVImage";`, `_ZTSSt9exception = "St9exception"`).
  Zero per-byte brace-lists remain (grep for `_ZTS… = {` is empty).
- **Half a declaration on L132 — FIXED.** No byte-list spill: each global is one string
  token on its line, L132 is legitimate `symbol_start` body, and no orphaned `NNh, … };`
  close line exists in any fixture.
- **Indentation / overlap — superseded by §9.** §9 decided to *keep* live `DECL_GLOBAL`
  fragments (explicitly the `_ZTI*/_ZTS*` RTTI globals) as data at their own line and flow
  decomp around them, rather than demote to `// stray:`. They now render as valid data
  decls, not laid as code. Residual is cosmetic: on L131 the three globals share a canvas
  row with `symbol_start`'s tail statements, and §9's "shallowest fragment" rule sits that
  row at column 0. §9-governed layout, not a §4 correctness bug.

Original defect notes:

- **Render as string.** `char const[9] _ZTS7XVImage = { 37h, 58h, 56h, 49h, 6Dh,
  61h, 67h, 65h, 0h }` is the string `"7XVImage"`. A `char[N]` global whose bytes
  are a printable run should render as a quoted literal, not a per-byte brace
  list. `initializerAt` takes the aggregate-spread branch for char arrays; detect
  char-element arrays and render via the string path.
- **Half a declaration on L132.** `_ZTS8XDVImage`'s brace block spread its bytes
  onto L132, but L132 is past `symbol_start`'s close line, so the decomp overlay's
  stray sweep (`r.startLine..closeLine`) never removes/demotes it — it survives as
  an orphaned `38h, ... };` line. The multi-line global collides with the function
  span rather than being demoted whole.
- **Indentation / overlap on L131/L133.** `symbol_start`'s crammed body sits at
  column 0 (no in-function indent on the cram), and the three `_ZTS*` globals pile
  onto the same close line, with the next function opener on L133. These
  compiler-generated RTTI globals are strays inside a function span and should be
  demoted to `// stray:` comments (or filed to their real home), not laid as code.

## 6. Class body attributed to a .cpp instead of its header (AppImage → main.cpp) — FIXED

gcc emits a class's `:Tt` definition wherever it's first needed; when that's a
.cpp (AppImage's full def landed only in appquery/main.cpp — appimage.h was never
BINCL'd as a *definition* source, only as line-entries), the header association is
lost and the body rendered in the .cpp.

`multiSourceHeaderHints` already recovers the header by majority-voting the N_SOL
source of line entries inside the class's method bodies (gcc emits `N_SOL("foo.h")`
bursts where methods inline header code — AppImage's destructors inlined into
main.cpp carry appimage.h entries). Two bugs blocked it, both fixed:

- The `cuSources.size < 2` guard skipped single-source classes, so AppImage never
  got a hint. Replaced with the correct predicate: only classes with a **.cpp
  definition source** need a hint; a def already in a header renders correctly via
  `id.source` and a hint could only drag it somewhere worse (this is why
  FileSystemEntry/FileSystemImage/VmInfo — defined in their headers — are left
  alone and stay correct).
- The vote counted inlined **stdlib** headers, so std::string/std::vector inlining
  hijacked it (XVImage voted basic_string.h 812 > xvimage.h 84; VmInfo stl_tree.h
  > vminfo.h). Split into a real-header tally and a stdlib tally (new
  `String.isStdMarkerPath` in Attribution, reusing `STD_MARKERS`): a real header
  always wins; the stdlib majority is used **only** to collapse a scattered std
  instantiation into one file, never to pull a single .cpp-local one into a stdlib
  header.

Net vs committed baseline (appquery): AppImage main.cpp→appimage.h, XVImage
basic_string.h→xvimage.h, VmInfo stl_tree.h→vminfo.h; everything else unchanged;
no bodies scattered into .cpp. The renderer's `effectiveSource()` and
`Attribution.keyFor` share the same hint map, so DTM category and skeleton file now
agree for these. Remaining latent divergence (renderer bypasses canonical
Attribution for the non-hint path) is not exercised by the current fixtures.

## 7. Shorten long templated type names via their typedefs (DTM-level, analyzer option) — DONE

Template instantiations dominate output width: `vector<std::basic_string<char,
std::char_traits<char>, std::allocator<char> >, std::allocator<...> >` etc. When a
typedef names such a type, store the typedef name in the DTM instead so both the
listing and the decompiler benefit.

`materialize/TypedefShortening.kt`: `typedefShorteningRenames(aliases, typeNames)` is
the pure core — canonicalises whitespace around template punctuation
(`canonTemplateName`, so gcc's inconsistent `< `, `, `, ` >`, `> >` matches), keeps
typedefs whose alias is strictly shorter than their target, and rewrites each target
onto its alias wherever it appears: the target type itself and, recursively, inside
every other templated name's parameters, applying the longest target first so nested
reductions compose (`map<int, vector<basic_string<…> > >` → `map<int,StringVec>`).
Only stabs-origin typedefs drive renames. Ghidra's PE loader applies a Windows
data-type archive (`windows_vs12_32`: PVOID, BYTE, WORD, LPSTR, CONTEXT, …), and
those would otherwise shorten base types (`unsigned char`→`BYTE`, `void *`→`PVOID`)
— not our business. The pass keeps only typedefs whose source archive is the
program-local one (`DataType.sourceArchive == dtm.localSourceArchive`); applied-archive
types carry their external archive. Dropped 22 Windows-driven renames on appquery.

Ghidra base types are never shortened either. A stabs `typedef long long fpos_t` /
`fpos` typedef would otherwise rename the built-ins `longlong`→`fpos_t`,
`ulonglong`→`ufpos_t`, `undefined`→`fpos` — and their short names corrupt siblings by
substring (`undefined`→`fpos` textually hits `undefined4`→`fpos4`; `longlong` hits the
distinct `long long int`→`fpos_tint`). Excluded via `dataType is BuiltInDataType ||
Undefined.isUndefined` on the typedef's target. Dropped 26 base-type renames (107→81).

Default template-argument elision (`vector<T, allocator<T>>` → `vector<T>`) is
deliberately **not** done: the defaults aren't derivable from stabs, so it would need a
hardcoded per-template assumption table.

When several typedefs name one target (libstdc++ aliases `basic_string<char, …>` as
`string`, `_Value_type`, `_ValueType`, …) the shortest alias wins — real appquery
output collapsed to `_Value_type` until this was added.

`TypedefShortener(dtm, sink)` reads the aliases/names out of the DTM and applies the
renames. Renaming a target onto its alias collides with the very typedef that names it
(the `string` typedef sits in the same category as the `basic_string` struct), so the
pass folds that typedef into its target first — `DataTypeManager.replaceDataType`
redirects every reference and drops the typedef, freeing the name. It also rewrites
**base-class subobject field names** (`_base_<Name>`/`_vbase_<Name>` only — not user
member fields), which embed the base type's name at build time and so aren't reached by
datatype renaming; without this the decomp still shows
`_base__Vector_base<std::basic_string<…>>`. Gated behind `OPT_SHORTEN_TYPEDEFS` (default
off), run in the materialize transaction after `materializeAll`, and enabled in the
skeleton/decomp integration pipeline so its output reads shortened.

Pure core factored into `TemplateNameShortener` (build subs once, `shorten`/
`shortenedOrNull` any string) so the same boundary-guarded rewrite serves datatype names
and base-field names. Pinned by `materialize/TypedefShorteningTest.kt` (pure, outputs the
renames) and `integration/TypedefShorteningProbeIntegrationTest.kt` (real fixture DTM:
dumps every rename to `build/test-output/typedef-renames/<fixture>.txt`, applies them,
asserts the std::string fold+rename landed).

The renderer also shortens (the skeleton spells types from the harvest AST, not the DTM,
so DTM renaming alone didn't reach it). `harvestTemplateShortener(harvest)` seeds a
`TemplateNameShortener` from the stabs typedefs themselves (typedef name → aliased type
name, restricted to template targets containing `<`, which excludes base-type aliases
without DataType lookups); `render/Type.kt`'s `render` threads it through and applies it to
type names/tagnames, and `Renderer` applies it to the type's own declaration name. Result:
appquery skeleton and decomp both drop to **0** `basic_string<char…>` (skeleton 47
`std::string`, decomp 173).

The "6 residual" `basic_string` once seen in the decomp were never un-renamed DTM types
(a post-apply DTM scan found none) — they were AST-rendered type *declaration* headers
(`class iterator_traits<std::basic_string<…>>; /* 1 bytes */`) the decomp file overlays;
shortening the declaration name closed them.

The rewrite is textual but boundary-guarded: each target matches only when not flanked by
identifier chars (`(?<![A-Za-z0-9_])…(?![A-Za-z0-9_])`), so a bare-identifier target can't
rewrite a substring of a longer name (`longlong` in `longlongint`, `Node` in `NodeList`) —
`>`-terminated template targets still match, bounded by `<`, `,`, `::`. (A plain `\b\b`
would fail here: template targets end in `>`, so a trailing `\b` requires a following word
char that valid names never have.) This is complementary to the base-type exclusion —
boundaries stop corruption, exclusion stops renaming the base type itself.

Follow-up (not done): a fully structural rewrite over parsed template args would be stricter
still than the boundary-guarded textual one. Over-eager but harmless aliases like
`random_access_iterator_tag`→`_Tag` remain a name-quality question, not correctness.

## 8. Stack/register local injection — status (working; caveats). Part B (attribution) — RESOLVED

**Re-verified (this pass).** Two unrelated topics live here.

*Part A (the title) — working.* Current appquery `main` still adopts the stabs names
(`major`, `trapsets`, `used`, `version`, `vminfo`, `xdv`, `xuv`, `minor`, `name`, `is_xuv`, `i`, …).
Only register-var (`N_RSYM`) partial-liveness mapping remains a possible future item.

*Part B (the AppImage attribution divergence, below) — RESOLVED by §6's shared hint.* AppImage now
**renders** in `…/imageutil/appimage.h` and its **DTM category** is the same `…/appimage.h/AppImage` —
the two paths agree. They weren't unified by pointing `effectiveSource` at `byLocation` (as the
note proposed) but by both consulting the shared `multiSourceHeaderHints` map (`effectiveSource` =
`hint ?: declSourceFile ?: id.source`; `Attribution.keyFor` = std → real-header → single → **hint** →
`lex-min/multi`). Residual: the paths are still separate code and *could* diverge for a hint-less,
real-header-less multi-source **struct** (`effectiveSource → id.source` vs `keyFor → lex-min/multi`);
§6 flagged this "not exercised by the current fixtures" and it still isn't. The `divergentCollisions`
dump surface is a different concern (content-distinct same-name bodies across CUs), not this split.

Verified the injected `LocalVariableImpl`/register locals are adopted by the
decompiler: appquery `main` shows 13/14 stabs stack locals by name (`major`,
`xuv`, `xdv`, `used`, `trapsets`, `version`, `vminfo`, `i`, …). This also confirms
the `getBaseStackParamOffset` frame-bias (#3) is correct — wrong offsets wouldn't
match storage. Remaining un-named slots are *not* failed locals: `local_f4`-style
slots are compiler SjLj exception-region indices (no stabs name), and
`uVar`/`iVar`/`bVar`/`pxxStack_` are decompiler SSA value-temporaries. Register
locals (`N_RSYM`) stick only partially — a register holds the source var over just
part of its live range, so the decompiler names it elsewhere. No further work
needed on stack locals; register-var liveness mapping is a possible future item.

Real root cause (from `registry.afters/appquery-registry.after.json`): the
**canonical registry already attributes it correctly** —
`"key": "/appimage.cpp/multi/AppImage"`. `Attribution.keyFor` (`Attribution.kt:76`)
sees AppImage's defSources as multi-source (appimage.cpp + main.cpp) with no real
header among them (gcc didn't BINCL appimage.h as a *definition* source, only as
line-entries), so case 5 routes it to lex-min `/appimage.cpp` + `/multi`. The
`winnerId = main.cpp,245` is just the representative TypeAst chosen for the
DataType — not where it should render.

The bug is that the **renderer bypasses this attribution**:
`RenderContext.effectiveSource()` uses `multiSourceHeaderHints[name] ?:
id.source.filename`, and with no hint falls to the winner's CU (main.cpp). So the
DataType lands in `/appimage.cpp/` but the skeleton renders in main.cpp —
divergent attribution from two code paths.

Fix: unify — have `effectiveSource()` consult the canonical attribution
(`typeResolver.byCanonicalKey` / `Attribution.keyFor`'s category) instead of
`id.source.filename`, so the skeleton file matches the DataType category
(appimage.cpp here). Separately, appimage.h would be preferable to appimage.cpp,
but that needs the header in defSources (it isn't) — a distinct BINCL-attribution
gap, lower priority than making the two paths agree.

## 9. Decomp layout regressions after source-line placement — DONE

Captured from `build/test-output/decomps/appquery/main.cpp` after the source-line
placement rework (commit 6335c83). Four issues:

- **Lost the `// ⇐ L NN` source-line annotation.** §2 tagged every decomp statement
  with the source line its instructions came from; the placement rework now sets the
  note only when the entry's source/line differs from the placement target
  (`note = entry?.takeIf { it.source != source || it.line != target }`), so a statement
  placed at its own source line shows no line number. Restore the explicit line-number
  comment on decomp statements (it confirms attribution even when the canvas line
  already matches).
- **Blank lines between grouped statements waste vertical space.** Placing each
  coalesced group at its source line leaves gaps (empty canvas lines) between groups —
  e.g. main.cpp has runs of blank lines around 155–166. Either compact the gaps or
  reconsider placement so the body reads densely instead of scattered down the span.
- **Indentation is flat, not block-level.** `indentFor(line)` is a flat 4 spaces for
  anything `inFunction`, so nested decompiler blocks (loops/ifs) don't step in and the
  crammed body sits at one column. Track `{`/`}` nesting depth from the clang token
  stream and indent decomp statements by bracket level.
- **Legit file-scope globals/types inside a function span get demoted to `// stray:`.**
  main.cpp L167 dumps `vm2_trapset_names` (L82), `vm3_trapset_names` (L152) and a run
  of type decls (L63–152) as `// stray:` comments on the close line, because the stray
  sweep (`r.startLine..closeLine`) treats every non-decomp fragment in the span as a
  stray. These are real declarations that fall within `main`'s (over-large?) source
  span — they should render at their own line, not be swept. Investigate whether
  `main`'s `closeLine` is inflated (SLINE attribution dragging header/inlined lines) or
  whether the sweep needs to exempt symbol/type fragments that own a distinct line.

### Finding: vm*_trapset_names are FILE-SCOPE statics, and `main`'s span is misattributed (CORRECTED)

Earlier note was wrong. The stab descriptor `:S` (`vm2_trapset_names:S(1,369)=ar…`) is a
**file-scope** static — `:V` would be the function-local one. All fourteen (`vm1`..`vm14`) carry
`:S`, are grouped together at file scope in the stab stream, and `vm1` (line 12) precedes `main`
(line 49). So they are **not** declared inside `main()`.

They only *appear* inside `main`'s span because that span is inflated by **cross-file line
misattribution**. `main`'s N_SLINE table interleaves `N_SOL <header>` blocks for inlined library
code — e.g. `N_SOL bitset` then `SLINE 166`, `SLINE 723`; `N_SOL basic_string.h`; `N_SOL
appimage.h` — and those header line numbers (bitset:166, …) are being attributed to *main.cpp*
line numbers. `main`'s real main.cpp lines run ~49–114; the span stretches to 166 from bitset:166,
overlapping the file-scope `vm2`/`vm3` arrays at main.cpp 82/152. The same bug lands libstdc++
typedefs (`typedef __true_type __Normal`, `__false_type _Trivial`) at bogus main.cpp lines
(426/448/488) instead of their header, so they render as main.cpp typedefs and aren't flagged
misattributed. Root fix is in the harvester's N_SOL/N_SLINE source tracking (attribute each line
entry / type / symbol decl to the N_SOL file in effect), not the render sweep.

### Decided direction (from user)

Rework `applyDecompilation` placement + `indentFor` to:

- **Bracket-level indentation**, K&R style: keep `{` at the end of the line (open braces at
  EOL) and step nested blocks in by `{`/`}` depth (from the clang token stream).
- **Group statements on the same source line onto one line**, BUT if grouping would leave
  blank-line gaps, **spread** instead to fill the vertical space (hybrid of the coalesce and
  source-line-placement approaches — compact where dense, spread where sparse).
- **Always** append `// L NN` at the end of every emitted line (restore the annotation
  unconditionally, at end-of-line not mid-line).

Relevant code: `Renderer.applyDecompilation` (placement loop ~399), `Renderer.indentFor`
(flat-4), `DecompTokens.compressedDecompLines`/`DecompLine` (token lines + addresses), the
stray sweep (~359), and `Format.kt` (`FragmentKind.DECOMP` note rendering).

### Resolved

Everything is read from the clang token stream / node tree, never the rendered characters —
that's the through-line. In `DecompTokens` + `Renderer.applyDecompilation` + `Layout`:

- **Indent = Ghidra's own nesting.** `DecompLine.depth` is the ClangLine's `indent` (its structural
  level, one space per level); placed decomp fragments use it verbatim, so nested blocks step in K&R
  style and the signature / close brace sit at column 0. No `{`/`}` character counting.
- **Wrapped lines rejoined structurally.** Ghidra wraps one long logical line (a fat `if` condition,
  a long call) across several ClangLines at deeper indent. `blockDepth()` — the count of enclosing
  plain `ClangTokenGroup`s (block groups; `ClangStatement`/`ClangVariableDecl`/… are distinct
  subclasses) — is equal for a wrapped line's continuations and their head, one deeper for a nested
  statement, and a sibling shares the indent. So `indent > head.indent && blockDepth == head.blockDepth`
  identifies a continuation; `compressedDecompLines` merges those onto one logical line (one address →
  one row), and braces still get their own rows.
- **Spread, capped at the close unless it would cram.** Statements on one this-file source line gather
  into a `DecompRun`; `spreadBlocks` reserves rows per run *size* (a whole `while` loop coalesced onto
  one source line gets its share of the interior blanks, not one crammed row while a small sibling
  wastes the space) and `placeRun` lays each run's lines one per row (braces on their own line) or crams
  where tight. The body stays inside the span when it fits, so nothing spills past the function's last
  line; when it would otherwise cram, placement borrows the blank rows after the function up to the next
  one (`end = if (sizes.sum() <= spanFree) closeLine else nextSpan - 1`).
- **A line's indent is its shallowest code fragment**, not the first-added one — so a function opener at
  column 0 sharing a row with an indented in-span global (`_ZTS*` RTTI names on the `names` L31 line)
  starts the row at the opener, not pushed in by the global. Comment-only fragments don't pull it in.
- **`// ⇐ L NN` on every emitted row**, naming the source line the instructions came from.
- **Legit globals kept.** The stray sweep keeps live `DECL_GLOBAL` fragments (function-local statics
  `vm2/vm3_trapset_names`, `__ioinit`, the `_ZTI*/_ZTS*` RTTI globals) as data at their own line and
  flows decomp around them; only type-decls / typedefs / misattributed fragments become `// stray:`.
- **Declarations by node type.** A declaration line *is* a `ClangVariableDecl` group (signature params
  excluded) — the old `has-a-ClangTypeToken` heuristic false-positived a `(uint)` cast in
  `else if ((uint)i < 4)`, so `groupDecls` mangled it into `uint )i<4)`.
- **Calling conventions stripped.** `content()` drops `__thiscall`/`__cdecl`/… (and its trailing
  blank), so a prototype reads `ushort Foo::m(...)`.
- **Ghidra's blank body lines dropped** — we space with our own placement.

Pure cores pinned by `LayoutTest.spreadOver`/`spreadBlocks`; verified against regenerated
`build/test-output/decomps/{appquery,unpackfile}`.

## 10. Post-diagnostics-refactor: audit every log() level — DONE

Swept every `log()`/`debug()`/`warn()`/`err()`/`degradation()` site (StabsImporter,
ClassBuilder, TypeRegistry, Harvester, TypeResolver, IncludeContext, DemanglerReplacer,
TypedefShortening). Rule applied: **WARN** for real anomalies (`unexpected-symbol`,
`unexpected-nfun/psym-rsym/lsym`, `stab-unknown`, `einc-unbalanced`, and the previously-silent
`global-applied-then-overwritten` — a write that didn't stick); **DEBUG** for benign structural
counters/traces (`base-empty-ebo*`, `inheritance-applied/failed`, `vptr-*`, `vfptr-*`,
`drop-record-*`, `referenced-aggregate`, `typedef-*-skip`, `replaced-demangler*`, the
`harvest-collisions-*-total` siblings, `class-build-name-collisions`, `vtable-templated-skip`);
**INFO** kept for genuine per-run summaries (`no-stabs`, `xref-stubs-synthesized`,
`inheritance-pseudo-fields-promoted`, `typedef-shorten` totals). Logs that merely restate an
adjacent `degradation()` WARN (`inheritance-failed`, `vtable-failed-<bucket>`,
`replaced-demangler-failed`) dropped to DEBUG to avoid double-reporting. Levels don't change
counters, so all baselines hold. Also fixed the stale "auto-bumps the counter" comment (removed —
the tag→counter contract is a general fact, not per-site) and a latent `$decl.name` interpolation
bug (was `decl.toString()+".name"`).

## 11. More log() calls should carry a bookmark address — DONE

Swept the WARN/ERROR (and leveled INFO) sites and passed the in-scope `Address` so they reach
Ghidra's BookmarkManager: `apply-error-<bucket>` (function entry), `function-create-*` +
`no-function`/`no-executable-block` (target addr), `method-calling-convention` (func entry),
`local-var-error`/`scope-comment-error` (func entry), `global-applied-then-overwritten` +
`apply-error` global/static create + `symbol-create-error`/`symbol-primary-error` (data addr).
Left address-less where none is meaningfully in scope: `parse-error` (a stab record has no memory
address), `class-*`/`vfptr-*` (type/layout, not code), and `vtable-symbol-scan-error`/
`vtable-rdata-scan-error` (the scan is *searching for* the address it failed to find).

## 12. Importer: are we actually renaming functions & globals? — DONE

Prompted by review. Findings:

- `StabsOptions.createImportedLabels` (default true) was **dead** — defined but never read.
  **Deleted** (no analyzer-option plumbing; renaming is core importer behaviour, not a toggle).
- **Functions were not renamed from stabs.** We applied return type / params / __thiscall and
  let Ghidra's demangler name mangled symbols, but plain names rode the PE symbol — so `main`
  showed as `_main` (Cygwin/PE leading underscore). Globals already got their stab name via
  `ensureStabLabel`; functions got no equivalent.

**Fix:** `applyAllSymbols`'s function loop now applies the stab name to *every* function —
`if (func.name != open.name) func.setName(open.name, source)`. The stabs are the authoritative,
underscore-free source, so we name from them rather than riding the PE symbol; this is
**PE-symbol-independent** (works on a binary stripped of its COFF symtab but carrying stabs).
Mangled names (`_ZN…`) are set raw and resolved to `Class::method` by the existing
`demangleMangledLabels()` pass that runs right after the loop over the whole symbol table — so
no mangled/plain special-casing is needed.

A first attempt used `ensureStabLabel` uniformly (as globals do); that **regressed** C++ names
(`FileSystemImage::fetch32` → raw `_ZN15FileSystemImage7fetch32ERK5Imagem`) because it adds a
*competing* label and force-sets it primary, shadowing the function symbol Ghidra had already
demangled. `setName` (renames the one primary) + the trailing demangle pass avoids that.

Verified across all six fixtures: `main`→`main`, every C++ method stays demangled, **0**
raw-mangled function definitions anywhere. appquery decomp diff vs baseline = only `_main`→`main`
(and its propagation into provenance annotations).

## 13. Struct/non-pointer by-value return uses wrong calling convention — DONE, but this note's ABI premise was wrong

**Correction, and the mechanism below is no longer what ships.** The note asserts gcc/MinGW i386
returns *every* by-value struct through the hidden pointer. It does not: mingw/cygwin set
`DEFAULT_PCC_STRUCT_RETURN=0`, so `-freg-struct-return` is the default and a POD (trivial for
calls) of size 1/2/4/8 really is returned in AL/AX/EAX/**EDX:EAX**. Only classes non-trivial for
calls — non-trivial copy ctor or dtor, so `std::string`, `list`, `vector` — go to memory,
*regardless of size*. The cspec's register return is therefore right for PODs and wrong only for
non-trivial classes. Counterexample in unpackfile: `FileSystemImage::root()` returns the 8-byte POD
`FileSystemEntry` in EDX:EAX with `this` at `+0x8` and a plain `RET`, and its caller consumes both
registers; a blanket `return.dataType is Composite` rewrites it wrongly. The cheap discriminator is
the terminating **`RET 0x4`** — gcc's callee pops the hidden pointer — plus
`f.stackPurgeSize == program.defaultPointerSize` in the predicate.

**And the implementation was reworked off custom storage.** `StructReturnAnalyzer` now installs a
calling convention as a spec extension (`__thiscall_memret` / `__cdecl_regret`, derived from the
function's own convention) via `SpecExtension.addReplaceCompilerSpecExtension` and calls
`setCallingConvention`; Ghidra lays out the hidden pointer and `this` itself. The
oversized-dummy `getStorageLocations` trick, the `ParameterImpl`/`ReturnParameterImpl` juggling and
`CUSTOM_STORAGE` described at the end of this section are gone. Two traps worth keeping: use
`f.return.formalDataType`, not `dataType` (on a forced-indirect return the latter is already the
hidden pointer), and `hasthis="true"` is required on the renamed model because auto-`this` is keyed
off the literal name `__thiscall`.

Original note, as written:

Methods returning a `string` by value (e.g. unpackfile `FileSystemEntry::name`, `children`) came
out with the **return `string*` in stack[4] and `this*` in stack[8]** — the hidden return-slot
pointer (RVO) modelled as a stack arg instead of via the struct-return ABI, so the real `this`
landed in a phantom `in_stack_00000008`.

Root cause: `x86gcc.cspec`'s output model register-returns any aggregate ≤8 bytes
(`EAX`/`EDX:EAX`) and only force-indirects (`FAIL`→`HIDDENRET_PTRPARAM`) a return >8 bytes. But
gcc/MinGW i386 returns *every* by-value struct/class through the caller-allocated hidden pointer.
So `std::string` (4B) and small `list` were register-returned by Ghidra while `vector`/`XVImage`
(≥12B) were correctly auto-injected. Ground truth: across unpackfile, 89 methods carry `this` at
frame `+0x8` and exactly the 5 by-value-aggregate returns carry it at `+0xc` — the extra pointer
slot is the hidden return.

Fixed as a **standalone Ghidra analyzer** (`StructReturnAnalyzer.kt`), independent of stabs and
gated to x86:LE:32 gcc (on SysV x86-64 small PODs really do return in registers, so it must not
run there — the box2d/xmltest ELF fixtures are left untouched). For each `Composite` return the
cspec did not already force indirect, it re-applies the function with custom storage mirroring the
large-return layout — a forced-indirect return + explicit `__return_storage_ptr__` first arg,
storages computed by the model itself from an oversized-dummy prototype so offsets aren't
hand-rolled. Runs after the Stabs Importer (`LOW_PRIORITY.after()`); idempotent via the
`hasCustomVariableStorage` guard. Verified: `name`/`children` now render
`T *__return_storage_ptr__, FileSystemEntry *this`; large returns unchanged; all integration
tests green.

## 14. `string` typedef breaks /Demangler/string replacement (regression, needs test) — DONE

Root cause pinned down: with `OPT_SHORTEN_TYPEDEFS` on, `TypedefShortener` renames the
`basic_string<…>` **struct** onto its `string` typedef's name (folding the same-category typedef
into the struct via `replaceDataType`, but the separate `/stabs/string` typedef in another
category survives). So two DataTypes end up named `string` — the surviving typedef and the renamed
struct it points at — and `TypeRegistry.findByName("string")` returned **two** matches. The
`/Demangler/std/string` stub's preferred-category (`/std`) matched neither, so findByName logged
`demangler-ambiguous` and returned null → `DemanglerReplacer` recorded `NoReplacement` and left the
stub in place.

**Fix (`TypeRegistry.findByName`).** A typedef and its own **resolved target** both matching is not
real ambiguity — they denote one type in two guises. After the preferred-category tiebreak fails,
drop any match a matching `TypeDef`'s `baseDataType` points at and keep the typedef; if exactly one
survives, return it. So `string`(typedef)+`string`(struct) collapses to the typedef, the stub is
replaced, and shortening + demangler-stub replacement coexist. Genuinely-ambiguous cases (two
unrelated structs) are unchanged — still logged and null.

**Tests.** `StringTypeProbeIntegrationTest` now builds its context with `shortenTypedefs = true`
(it used `defaultContext()`, shortening off, so it never exercised the path). New hermetic
`DemanglerReplaceIntegrationTest.testDemanglerStubReplacedWhenTypedefAndRenamedTargetCollide`
registers a `string` typedef + a same-named renamed struct + a `/Demangler/std/string` stub and
asserts the stub is replaced — verified red before the fix, green after. Existing
`StabsAnalyzerTests.demanglerStringReplaced*` (shortening off) and the unit suite stay green.

## 15. Canonicalize source-file paths (one header, one output file) — DONE

**Symptom.** A single header is emitted as *two* skeleton/decomp files under two path
spellings, splitting its content. `packfile` renders both `dspinfo.h` (bare) and
`E__work_cc_devtools_devtools-bluelab-7-0_result_include_dspinfo_dspinfo.h` (full path):
the full-path file gets the real `:T` definitions (`enum KalimbaArch { … }`,
`class dspinfo { …fields… }`) while the bare file gets only forward-decl stubs
(`typedef struct dspinfo;`).

**Root cause.** gcc spells the same physical header two ways across CUs — the full
include path where it compiles the definitions, the bare `#include "dspinfo.h"` spelling
where another TU only forward-references it. The two `N_BINCL`s carry **different
checksums** (149935 vs 865864 — each CU's expansion differs), so they can't be merged by
checksum. `SourceFile`/`HeaderFile` (`parse/IdInterface.kt`) key by the raw `filename`
string, and everything downstream (`Harvest.lineEntries` keys, `staticsByCu`,
`typeAsts[].id.source`, `TypeResolver.functionSource`/`effectiveSourceFor`,
`Renderer.sources`) inherits that, so one file becomes two sources → two output files.

**Fix — canonicalize to the shortest spelling.** Build one canonicalization map over all
source filenames and route every source-string use through it:

- A **bare** name (no `/` or `\`) that is the **basename of exactly one full path** also
  present canonicalises to — and displays as — the **shorter (bare) name**; the full-path
  source folds into it. This is the chosen policy: shorter name wins.
- **Guard:** if two distinct full paths share a basename (`a/config.h`, `b/config.h`), do
  **not** merge them — the bare name is ambiguous; keep them separate (and keep whatever
  the raw keying does today). Only a *unique* basename→full-path match merges.
- Do not rely on checksum (they differ here). Basename identity is the signal.

**Where.** Cleanest as a single map computed once (TypeResolver is the natural home — it
already derives `functionSource`/`effectiveSourceFor`) and applied at every point a source
string is used as an output-file key or per-source filter: `Renderer.sources`, and the
RenderContext filters (`functionSource[it] == source`, `lineEntries[source]`,
`effectiveSourceFor(it) == source`, `symbolsByCu[source]`). `lineEntries`/`staticsByCu` are
keyed by the raw string, so either re-key them by canonical name or look up via a
canonical→raw fan-in. Extract the pure canonicalisation (list of filenames → map) so it's
Kind-1 testable.

**Verify.** `packfile` decomp/skeleton has exactly one `dspinfo.h`, carrying the full
`enum`/`class` definitions (no separate mangled full-path file, no forward-decl-only file).
No fixture loses content.

**DONE.** Pure `canonicalizeSourcePaths(filenames)` in `harvest/Attribution.kt` (Kind-1, pinned
by `SourceCanonicalizationTest`) builds raw-spelling → canonical-spelling: a bare basename that
matches **exactly one** full path folds that full path onto the bare name; two full paths sharing
a basename leave the bare name ambiguous → nothing merges; everything else maps to itself.
`HarvestIndex` computes it once (`sourceCanonicalization`, seeded from `lineEntries.keys`,
`symbolsByCu.keys`, `functionSource.values`, and each type's `effectiveSource()` — none depend on
canonicalization, so no cycle) and exposes `canonicalSource(raw)` plus canonical-keyed fan-in views
`lineEntriesByCanonicalSource` / `symbolsByCanonicalSource` (re-sorted by (line, addr)). `Renderer`
canonicalises `sources`, and every `FileRenderer` source comparison routes through `canon(...)`:
`rawFuncs` (`functionSource`), `lines`/`symbols` (fan-in views), `typeDecls` (`effectiveSourceFor`),
param/local `sourceFile`, `refOf`/`ownLine` decomp tags, `emitIncludes`, `reportAnomalies`, and
`FunctionSpans.of` (canonicalizer param, applied in `rawSpan`). Verified: `packfile` renders one
`dspinfo.h` with `enum KalimbaArch` + `class dspinfo` (full-path spelling gone); appquery folds
`bits64image.h`/`vminfo.h`/`xdvimage.h`, `vminfo.h` genuinely merges 9+32-line spellings losslessly
(fragments on shared source lines concatenate; content is the union). Confirmed no loss by diffing
each fold against a clean-HEAD regeneration (the two spellings' union == the merged file). Ambiguous
`image.h`/`xvimage.h` (two full-path spellings each) correctly stay separate. Fixtures with no
basename collisions (xmltest) are byte-identical to clean HEAD (canon is identity there).

**Follow-up (option + threading cleanup).** Gated behind analyzer option `OPT_CANONICALIZE_PATHS`
(`StabsOptions.canonicalizePaths`, default **on**); off → `sourceCanonicalization` is empty →
identity everywhere → the pre-§15 two-files-per-header behaviour. To drop the per-comparison
`canon(...)` threading, `functionSource`/`effectiveSourceFor` now **return canonical** (private
`functionSourceRaw`/`effectiveSourceRaw` seed the canon map to avoid a cycle) and `Renderer.sources`
reads the canonical-keyed views, so the keyed-lookup sites (`sources`, `rawFuncs`, `typeDecls`,
`emitIncludes` type deps) compare canonical-to-canonical with no `canon`. The residual `canon(...)`
calls are irreducible per-record raw-source checks — `LineEntry.source` (`FunctionSpans.rawSpan`,
`refOf`, `ownLine`, inlined-include list) and `id.source.filename` (`reportAnomalies`) — kept raw
because canonicalising those fields would ripple into the delicate `multiSourceHeaderHints` vote
(keyed on raw `id.source`/N_SOL spellings; §6/§17).

**Attribution-follows-canon: attempted, reverted.** Wiring `sourceCanonicalization` into
`Attribution.keyFor` (so a folded header's DTM *category* also collapses to the bare name, unifying
with §8) **regressed type resolution**: folding `dspinfo`'s category made the decompiler render
`dspinfo`/`ChipLookupResult` as anonymous `Anon_dspinfo_N_hash` (a §14-style findByName/collision
fragility surfaced by the category move). appquery's RegressionTest stayed green, but packfile decomp
broke, so it was backed out — canonicalisation stays **render-only**. Unifying DTM attribution would
need the findByName/collision robustness sorted first (own change).

**Companion (likely same parser N_SOL-tracking family, verify together — see §9 finding).**
Cross-file *line* misattribution: `main`'s span inflates to L166 because `N_SOL bitset;
SLINE 166` (bitset line 166) is attributed to *main.cpp* L166 (main's real main.cpp lines
end ~114), which is also why the file-scope `vm2`/`vm3` arrays (main.cpp 82/152) render
"inside" main, and why libstdc++ typedefs (`__true_type __Normal`, `__false_type _Trivial`)
land at bogus main.cpp lines 426/448/488 instead of their header. `LineEntry` already carries
`source`; confirm the parser tags each SLINE with the *active* N_SOL (not the enclosing CU)
and that `FunctionSpans`/attribution filter on it. If the path-canonicalisation above changes
how `dspinfo.h`-style lines are tagged, re-check these at the same time.

## 16. Unresolved enum XRef stubbed as a struct → wrong return ABI — DONE

Original hunch: `AppImage::image_type`'s return `vm_image_type` (an enum only ever forward-referenced,
never defined) was "missing." Investigation showed it was worse than missing: the placeholder existed
with the right *name* but the wrong *kind*. `makePlaceholder`'s `else` branch stubbed every unresolved
XRef as a `StructureDataType`, ignoring the XRef's `kind` — so the enum-kind `vm_image_type` became an
empty **struct** (a `Composite`). That tripped §13's StructReturnAnalyzer, which forced the hidden
return-pointer ABI onto `image_type`: it rendered `vm_image_type *image_type(vm_image_type *__return_storage_ptr__, AppImage *this)`,
returned `(vm_image_type *)0x1`/`0x0`, and — the giveaway — **every caller was corrupted**, passing
`this` into the return-slot and losing the real `this` to a phantom `in_stack_*` (the exact §13 failure
mode, mis-applied to a function that returns a scalar enum, not a struct).

**Fix** (`makePlaceholder`): an unresolved `XRef` whose `kind == AggrKind.ENUM` stubs as an
`EnumDataType`, not a `Structure`. Then it's not a Composite, StructReturnAnalyzer skips it (verified by
instrumenting `needsHiddenReturn`: `image_type` return = `EnumDB`), and the decomp becomes correct:
`vm_image_type AppImage::image_type(AppImage *this)` / `return 1;` / `return 0;`, callers
`vVar2 = image_type(this); if (vVar2 != 0)` — no phantom `this`, no pointer compares. Registry confirms
`/stabs/vm_image_type` is now `EnumDataType` (len 4). So §16 was a real issue after all, just mis-framed
as "missing" rather than "wrong kind → wrong ABI."

## 17. Typedefs misattributed into a .cpp (`typedef __true_type __Normal`) — DONE

Template-instantiation typedefs (`__Normal`, `_Trivial`, `_ValueType`, `_Is_POD`, …) rendered as
top-level decls in a .cpp at bogus line numbers (main.cpp:426/448/488). `isStale` (activity-extent)
couldn't catch them: the same misattributed SLINEs inflate the extent past the typedef line. Fixed two
ways, both principled (no name/reserved-identifier heuristic):

- **Attribution from `declSourceFile`.** Each typedef TypeAst already carries the N_SOL-effective
  source at definition time — for `__Normal` that's `bits/basic_string.h`, the real header, even though
  `id.source` is the CU. `TypeResolver.effectiveSource()` now prefers `declSourceFile` for non-struct,
  non-enum decls (typedefs), so they render in their header. Structs keep the §6 hint path; enums are
  deliberately left out — their `declSourceFile` is *itself* a .cpp (harvest-level misattribution), so
  moving them just shuffles between two wrong .cpp files (see §9/§15 root cause).
- **Multiplicity dedup.** The residual copies whose `declSourceFile` is a .cpp appear several times in
  one file (one per instantiation, at distinct bogus lines). `emitTypedefs` now dedups by
  `(alias, target)` — not the declLine the old dedup keyed on, which is why it never fired — collapsing
  the copies to one and flagging it `stale N_SOL?` (skeleton) / trimming it (decomp). Headers keep
  theirs (they're the canonical home). Verified: appquery main.cpp no longer carries them; decl set
  across all files unchanged (nothing lost); enums unmoved; RegressionTest green.

Residual: single-occurrence .cpp-attributed instantiation typedefs (no header sibling) remain — not
structurally distinguishable from a user typedef without a name heuristic.

## 18. Decomp layout: wrap crammed conditions; drop synthetic brace tags — DONE

Two fixes in the decomp overlay (`placeRun` + `Layout.wrapDecompLine`):

- **Wrap long conditions into the blank rows.** A long `if` condition that Ghidra wraps and §2's
  `compressedDecompLines` rejoins onto one 300-char row was crammed on a single line while the run's
  blank rows sat unused (`AppImage::image_type` L25). `placeRun` now, when a run has more free rows than
  lines, breaks an over-long statement at its **top-level `&&`/`||`** boundaries (paren/bracket depth
  tracked so a boolean inside a call's args never splits) — operators end the row (K&R), continuations
  step in, the trailing `{` stays. Dense runs (no spare rows) are untouched, so nothing already-tight
  regresses. Pure core `wrapDecompLine` pinned by `LayoutTest`.
- **Structural braces carry no source tag.** A bare `}` has no instructions and no stabs line — its
  `DecompLine.address` is null — so `placeRun` no longer stamps it with the run's source line. A `}` on
  the synthesised close line (`endLine+1`) was tagged with the last statement's line, reading as an
  off-by-one (`}` at L33 tagged `⇐ L 32`). Now only real statements (incl. wrapped continuation pieces,
  which keep their statement's address) carry `⇐ L NN`.

## 19. Decomp `#include`s from type dependencies, not just inlined code — DONE

The decomp `#include` list was derived only from headers whose code got **inlined** (non-.cpp N_SLINE
sources), so a .cpp that calls everything out-of-line (appimage.cpp) got **none**. `emitIncludes` now
also walks each function's signature/local types and resolves them to their defining header: an `XRef`
forward-decl via `TypeResolver.byXRef` (the `this` param bottoms out at `XRef("AppImage")`, no id), a
`Ref`/`InlineDef` via id, plus the resolved type's base classes. appimage.cpp → appimage.h + its type
deps. No filename heuristic — the type name resolves to its actual definition's source.

## 20. Unify duplicate type identities across header spellings (anon vs named) — DONE

gcc emits one physical header two ways (§15) with *different* N_BINCL checksums, so one logical
type gets several `GlobalTypeId`s: a **named** struct/enum in one spelling
(`.../include/dspinfo/dspinfo.h/dspinfo`), an **anonymous** copy in another (`Anon_dspinfo_4`, the
InlineDef target of a `typedef`), plus `typedef …;` aliases. `byLocation` groups by
`(category, ghidraName)`, so these land in *distinct* groups → the DTM materializes several
DataTypes for one type. Ghidra's decompiler picks a struct/enum's **display** name by resolving
across *all* same-named DataTypes plus the typedef graph, so the duplication is not inert: a
function returning `dspinfo` renders `Anon_dspinfo_4 *`, and — because the resolution is global —
naming/perturbing one type deterministically flips *unrelated* ones (`EnumDSPRev` → `Anon_dsp_rev_1`).
This is why attribution-canon (folding DTM categories by source path, §15's DTM cousin) regressed:
it only fixed the *some* spellings that folded by basename, leaving the rest duplicated.

**Fix — unify by content identity, early, before the DTM (three parts):**

- **`TypeResolver.mergeContentEquivalentGroups`** (the core). After the initial
  `keyForAst` grouping, collapse groups by **content hash**: within each content-equivalence class,
  if exactly one distinct *named* `ghidraName` appears, merge every group in the class — including
  **anonymous** ones, which carry no name for `keyForAst` to match — into that named group's slot
  (largest/most-resolved winner). So the anonymous `dspinfo`/`EnumDSPRev` copies alias to the one
  named DataType, and no second DataType is ever created. Content — not source path — is the signal,
  so it's path-canonicalization-independent and reaches headers that don't fold by basename. Classes
  with two distinct real names (coincidentally identical layout) or no named member are left alone.
- **`Harvester.nameAnonymousTypedefTargets`** (`anonymousTypedefTargetNames`, pure, Kind-1 tested).
  `typedef struct {…} Name;` (InlineDef) and `typedef enum {…} Name;` (a separate anon enum + a
  `Ref` typedef) both name their anonymous aggregate after the typedef — handles the *sole*-anon
  case (no named counterpart for the merge to find) and lets same-name merging compose.
- **`DataTypeRegistry` typedef-skip.** The typedef materialization phase no longer registers a `/stabs`
  `TypedefDataType` whose target already carries that exact name — that duplicate is precisely the
  same-named DataType that destabilises the decompiler's display resolution.

**Verified.** packfile `dspinfo.c`: `dspinfo * dspinfo_from_rev(EnumDSPRev rev)` — both named, **zero**
`Anon_*` in the file (was `Anon_dspinfo_4 *`/`Anon_dsp_rev_1`). xmltest: **56 fewer** anonymous-typed
degradations (`local-typed-anonymous` 40→0, `param-typed-anonymous` 16→0). No degradation regressions
on any fixture; RegressionTest green after one benign baseline bump (`xref-base-tag-resolved` 37→41 —
more XRefs resolve once types unify). Done **without** attribution-canon: the merge is content-driven,
so the DTM stays keyed on raw spellings and the render §15 path canonicalization (output-*file* dedup,
an orthogonal concern) is unchanged.

## 21. Blank anonymous type names + enum double-registration (diagnosed via RegistryDump)

The §20 content-merge never fired for **enums** (`EnumDSPRev`, `KalimbaArch`, `ChipLookupResult`,
box2d `b2BodyType`/`b2ShapeType`). Root cause, found by extending `RegistryDump` (RegressionTest) with a
grouping-diagnosis surface — per-group content hash / members / anonymous-count, content-hash classes
spanning >1 group, source folds, and duplicate-named DataTypes — rather than by eyeballing decomp:

- **Fixed: blank anonymous names.** gcc emits an anonymous aggregate/enum with a *whitespace* tag name
  (`" "`), not empty. `Cursor.readSymbolName()` returned it verbatim, so `name = " "` passed
  `isNullOrEmpty()` as "named" — the §20 merge counted it a distinct name (blocking the merge) and
  `nameAnonymousTypedefTargets` skipped it. `Parser.parseSymbol` now normalises a blank symbol name to
  `""` (`readSymbolName().ifBlank { "" }`), so "anonymous" is uniformly `name.isNullOrEmpty()`. The dump
  then shows the enum groups collapsing to one (`EnumDSPRev` members 2→3, no enum class spanning >1
  group). Degradation-neutral across fixtures; `xref-base-tag-resolved` 41→49 (more XRefs resolve once
  types unify — baseline bumped).

- **DONE: enum double-registration → `.conflict`.** `b2BodyType` was **one** `byLocation` group
  (18 members, `distinct=1`) yet materialized as **two** DataTypes at the identical `/src/body.h/b2BodyType`
  slot → Ghidra `.conflict` (`b2BodyType`/`b2ShapeType`, `EnumDSPRev`). Root cause: `materializeAll`
  registered **struct** placeholders into the DTM up front and filled them *in place*, but **enum**
  placeholders were left unregistered and `materializeEnum` built a *brand-new* `EnumDataType`. The empty
  placeholder leaked into the DTM via any struct-field/param `Ref` resolved (through `tryGetExisting`)
  before the winner materialized, colliding with the filled enum under `register`'s `KEEP_HANDLER`.
  **Fix** (`DataTypeRegistry.kt`): register enum placeholders up front like structs (`raw is Enum`), keep the
  placeholder an `EnumDataType` sized correctly at creation in `makePlaceholder` (also fixes the latent
  `-fshort-enums` case that fell to a `Structure` stub), and `materializeEnum` fills that one registered
  object in place. Verified: **zero `.conflict`** across all six fixtures' decomp; `duplicateNamedTypes`
  no longer lists any enum (only same-simple-name methods at distinct class categories, and the pre-existing
  benign `char → /char` primitive-typedef path); all integration baselines green.

- **Drift, 2026-08-25: "zero `.conflict`" no longer holds corpus-wide.** That was verified on the
  six-fixture corpus; on today's 24, `dtm-conflicts-created` is **30 across 13 fixtures** and
  `dtm-conflicts-post` **33 across 15** — 8 on crypto_mi_test_gcc421_fullstabs and 8 on its stripped
  twin, 3 on each xmltest_gcc421_fullstabs, 1 elsewhere. `dtm-conflicts-pre` is 5, so most are ours.
  `fewConflictRenames` still passes because it asserts `< 25` *per fixture*; its comment
  ("corpus-wide it sits at 0") is the stale part. Not necessarily this section's enum bug returning —
  §46 records a different `.conflict` fork path — but nothing owns the new ones, and
  `duplicateNamedTypes` already dumps the names, so diagnosing this is a read, not an investigation.

## 22. Single-arbiter attribution: canon at the data layer, §20 merge folded — DONE

Plan `zesty-tinkering-sparkle` (single-source-of-truth attribution, remove canon threading, robust
grouping). The §15/§20 work had left three overlapping attribution/canon paths and a `canon()` footgun
threaded through 8 render sites.

- **Phase 1 — canon once, at the data layer.** New `Harvester.canonicalizeRenderSources()` post-pass
  (after `nameAnonymousTypedefTargets`, gated by `canonicalizePaths`) folds `LineEntry.source` /
  `SymbolRecord.sourceFile` and re-keys `lineEntriesByFile`/`staticsByCu` to canonical once; the fold map
  is retained on `Harvest.sourceCanonicalization`. `id.source`/`GlobalTypeId` stay **raw** — DTM identity,
  content hash, and §20 grouping are content/id-based, not path-based.
- **Phase 2 — render de-threaded.** `Renderer`/`FunctionSpans` revert to ~`af16e9e`: no per-record
  `canon()` (`it.source == source` just works, the fields are already canonical).
  `TypeResolver.{lineEntriesByCanonicalSource,symbolsByCanonicalSource,canonicalizePaths}` removed;
  `effectiveSource` memoised once as `effectiveSourceByType`.
- **Phase 3 — §20 merge folded.** `mergeContentEquivalentGroups` inlined into a single `byLocation`
  pipeline (same comparators/condition — provably equivalent).

**Attribution stays raw — the crux.** `multiSourceHeaderHints` feeds `Attribution.keyFor` (DTM category)
and is keyed on raw `id.source`/N_SOL spellings, so it's computed **before** Phase 1's rewrite (extracted
to a pure `multiSourceHeaderHints(typeAsts, openFunctions, lineEntries)`, stored raw on `Harvest`).
Canonicalising the hint would leak §15 folding into DTM categories — the "attribution-follows-canon" §15
tried and reverted. Canon is render-only; type dedup is content-based (§20), not path-based.

**Dump made deterministic.** `RegistryDump` no longer stores the raw `Objects.hash` ints
(`CanonicalGroupEntry.contentHash`, `HashClassEntry.hash`): they're a JVM-run-nondeterministic hash of
enum members, valid only for equality/grouping within a run. It now buckets by hash equality and sorts on
`distinctNames`, so a HEAD-vs-branch dump diff is a real audit trail.

**Verified — the dump diff, not decomp text.** `RegistryDump` grouping/folds/counts structurally identical
to HEAD across all fixtures (only the now-removed hash ints moved); skeletons byte-identical;
`DegradationDumpIntegrationTest` + demangler/typedef-shortening/idempotence/type-registry + unit tests
(`SourceCanonicalization`/`Attribution`/`AnonymousTypedefTargetNames`) green. `StabsAnalyzerTests` == HEAD,
including the pre-existing `xapasmcsr` CONCURRENT `xref-base-tag-resolved`=41-vs-baseline-[49] flake, which
reproduces on unmodified HEAD (baseline too tight for CONCURRENT demangler-order nondeterminism). Decomp
`*`/`**` return-pointer wobble is Ghidra decompiler nondeterminism (HEAD single-fixture ≠ HEAD full-suite),
not attribution — which is why the deterministic dump, not decomp text, is the audit surface.

## 23. C++ ABI: itanium model is flat single-vtable — the vbase half is DONE, the MI half open

**Audit 2026-08-25: the first bullet below is stale.** `layVtable` no longer assumes the record
starts at `offset_to_top`. It locates the rtti header by scanning up to `MAX_VTABLE_PREFIX_WORDS`
(64) words from `_ZTV` for the slot holding a `_ZTI…`/typeinfo symbol, takes `offset_to_top` as the
word before and the address point as the word after, and lays each preceding word as an
`offset_to_top`-typed datum commented `vbase/vcall offset`; it falls back to the canonical
`2*ptr` shape only when there is no rtti to find (templates). That is what `885a649`
(`vftableLabelsSitOnTheAddressPoint` failing on iostream), `67cd457` and `ddaa01a` were. A class
with a virtual base anywhere in its hierarchy — anything derived from an iostream — is the case
that drove it, so this is exercised, not theoretical.

Still open, and genuinely: **secondary vtables** (non-primary bases under MI), **VTT** and
**construction vtables**. The original reasoning for not modelling them stands unchanged below.

Original note, as written:

The `materialize/itanium/` package models the Itanium vtable as a single flat record
(`offset_to_top` + `rtti` + one embedded `_vftable` function-pointer array), applied at the
`_ZTV` symbol. Verified spec-correct (itanium-cxx-abi.github.io/cxx-abi/abi.html) for classes
**without virtual bases and with single inheritance** — the whole gcc 3.4.4 corpus. Struct
*layout* does carry virtual bases (`_vbase_` fields, `BaseDecl.isVirtual`); the vtable
*consequences* of virtual/multiple inheritance are not modelled:

- **Vcall/vbase-offset entries** (negative offsets, before `offset_to_top`): a virtual-base
  class's `_ZTV` symbol points at the true start, which now has these leading entries, so our
  record (starting at `offset_to_top`) would be mis-registered. Degrades, doesn't crash.
- **Secondary vtables** (non-primary bases under MI), **VTT**, **construction vtables**: not
  emitted. These only exist with multiple/virtual inheritance.

Not modelled deliberately: the vcall/vbase/VTT lowering is ABI-level, not source-level, so it
isn't in the stabs — recovering it means the memory-scanning machinery of Ghidra's
`RTTIGccClassRecoverer` we chose *not* to port (stabs already give us the class model). Zero
payoff on single-inheritance-dominant BlueCore code; revisit only if a virtual-base class shows
up in a fixture.

## 24. Last-resort RTTI typeinfo wiring — Level B DONE, the vtable link and Level A open

**Audit 2026-08-25: this section's header was wrong — `Rtti` is wired.**
`DataTypeRegistry.substitute()` returns `rttiStructs.typeInfoLayout(ghidraName)` for an ast gcc
references but never defines, logging `rtti-pseudo-substituted`, and the counter fires on **15 of
24 fixtures**, 705 substitutions in total: crypto_mi_test_gcc345 150,
xmltest_gcc345_fullstabs 51, locale_test_gcc345_fullstabs 50, appquery 9, xapasmcsr 8,
unpackfile/packfile 7. Level B — the common case, a typeinfo global whose
pseudo *type* is stubbed — is done, and it went further than the plan: `typeInfoLayout` also reads
the base count out of a `__vmi_class_type_info_pseudo<N>` **name**, so the VMI shape is covered
without a memory read.

Two pieces remain:

- **The vtable `rtti` field still points at nothing.** `layVtable` lays that slot as a bare
  `PointerDataType(dataTypeManager)`; its own doc comment says "the rtti pointee stays an untyped
  `void*` until backlog §24 wires it". Now that the structs materialize, pointing the slot at the
  class's typeinfo struct is the small remaining half, and it is the half a reader sees.
- **Level A proper** — no typeinfo global at all, base count read from the applied typeinfo Data's
  `numBaseClasses` (component index 3), cf. `RTTIGccClassRecoverer.updateVmiTypeinfo`. No memory-read
  path exists. Still the rare case: the corpus shows no `__vmi_…_pseudo` outside the name-derived form.

Original note, as written:

`itanium/Vtable.kt`'s `Rtti` builds the authoritative `__cxxabiv1` typeinfo structs
(`classTypeInfoStructure` / `siClassTypeInfoStructure` / `vmiClassTypeInfoStructure(n)` /
`baseClassTypeInfoStructure`) but nothing consumes them yet — the vtable `rtti` field points at
`Undefined4*`. They are the implementation of last resort for the gcc-internal typeinfo records
the stabs don't fully carry. Two levels, in priority order:

- **Level B — typeinfo global present, its pseudo *type* stubbed (the common case on our exes).**
  The stabs *do* emit the typeinfo globals — `_ZTI8CSegment`, `_ZTI4Inst`, `_ZTI8ExprInst`,
  `_ZTI10CLexStream`, … — each typed `struct __{class,si}_class_type_info_pseudo const`. But the
  gcc-internal pseudo struct types aren't in the stabs (libsupc++ built without them), so they land
  as unresolved XRefs (`type=/stabs/__si_class_type_info_pseudo`) and get stubbed opaque. Fix:
  substitute the matching `Rtti` impl for the stub, keyed by XRef name — hook the same
  unresolved-XRef substitution path as commit 8936ae1 (unresolved enum → `Enum` not `Struct`).
  Layouts already match gcc's pseudo shape: `__class_type_info_pseudo` = {typeinfo-vtable-ptr,
  __type_name} ↔ `classTypeInfoStructure` (2 ptrs); `__si_…_pseudo` adds `__base_type` ↔
  `siClassTypeInfoStructure` (3 ptrs). Fixed member counts — **no memory read needed.**
- **Level A — no typeinfo global at all, or a VMI one.** Only here do you need the base count:
  size via `RttiStructs.vmiClassTypeInfoStructure(numBaseClasses)`, reading it from the applied
  typeinfo Data's `numBaseClasses` field (component index 3), cf.
  `RTTIGccClassRecoverer.updateVmiTypeinfo` / `getNumberOfBaseClasses` (the essence of the old
  commented `getVmiNumBaseClasses` stub, since removed). xapasmcsr shows **zero** `__vmi_…_pseudo`
  — single-inheritance corpus — so this is the rarer path.

Then point the vtable `rtti` pointee at the class's typeinfo struct instead of `Undefined4*`.
Behavioural: shifts regression counters — regen baselines with `-PregenerateBaselines=true`.

## 25. `_ZTV` symbols with no stabs class are never annotated — DONE

**Fixed by a post-group sweep; and the diagnosis this section carried was wrong on both halves.**

`buildAndApplyVtable` runs per `LocatedType`, i.e. only for a class we harvested a `T`-stab body
for. libsupc++ and libstdc++ link without stabs, so their polymorphic classes own a real `_ZTV`
that nothing ever visits. `ClassBuilder.sweepUnclaimedVtables` now runs after the group pass over
every `Itanium.vtableClassOf`-matching symbol whose address no group claimed (`claimedVtables`),
and lays it.

**Measured, `unpackfile.exe`: 5 `vtable-applied` → 5 applied + 53 swept = all 58 `_ZTV` symbols, 0
empty.** Slot counts check out against the ABI (`std::ostream` = 2, its two dtor entries;
`__cxxabiv1::__class_type_info` = 9).

### What the previous note got wrong

It claimed most of the 400 `vtable-failed-truly-missing` was a name-construction gap — no STL
substitution shorthand (`Ss`/`Si`/`So`) in `ztvCandidates` — "cheap and testable", to be measured on
a fullstabs/stripped pair. Both halves are false, and one `nm` each shows it:

- **Stripped fixtures have no symbol table at all.** `nm xmltest_gcc421_fullstabs_stripped.exe` →
  *no symbols*. Neither a candidate list nor the demangled index can resolve a `_ZTV` there; the
  121 failures are unreachable by name, full stop. Nothing name-shaped was ever going to move them.
- **The 17 failures on the unstripped twin have no `_ZTV` symbol in the binary either** —
  `__fundamental_type_info`, `__array_type_info`, …, `stringbuf`, `istringstream`,
  `char_producer<char>`. They are correctly bucketed `truly-missing`. Restoring the shorthand moves
  zero.

The shorthand also does not need restoring for its original purpose: both sides of the
`vtableAddressByClass` lookup come from the *same* demangler — `qualifiedClassName` off a member's
mangled name, the key off the `_ZTV` symbol — so `_ZTVSo` and `std::basic_ostream<char,…>` already
meet. That is why `885a649`'s `ztiCandidates` table was removable in `ddaa01a` with no loss.

### Slot typing, and the three invariants it has to satisfy

With no method list the slots are typed from the targets: the applied `Function`'s signature where
auto-analysis produced one, else what the target's own mangled name declares (`Demangler`), which is
all a stabs-free libstdc++ vtable ever has. Array length is inferred — `vtableSlotTargets` runs while
the words point into executable memory, which stops at the next record's `offset_to_top` (0) or rtti
pointer (into .data). Three things the first cut got wrong, each caught by an existing test:

- **A pure-virtual slot is not untyped.** `__ZTVSt21__ctype_abstract_baseIcE` is `[0, &_ZTI…, D1Ev,
  D0Ev, 12× ___cxa_pure_virtual]` — "2/14 typed" was accurate, the class is abstract. `void*` there
  reads as a failure to type it; `__cxa_pure_virtual` is a real function and gets a real (empty)
  definition.
- **One FD name per demangled leaf forks a `.conflict` per overload.** `std::num_get` has six
  `do_get`, `std::ctype` two of each `do_is`/`do_widen`/… — 32 conflicts on unpackfile against a
  baseline of 1.
- **Field name and pointee FD name must agree** (`atLeastOneVtableStructApplied`; RecoveredClassHelper
  matches slots to definitions by name for the shift-S round-trip). So the dedup suffix has to apply
  to both, not just the field.

### Side effect: the gcc-12 missing-method-stab fixtures

`crypto_mi_test_gcc421.exe` and `xmltest_gcc421.exe` were `@ExpectedToFail` on
`atLeastOneVtableStructApplied` because gcc 12 omits the method stab section for polymorphic classes,
leaving nothing to build slots from. The sweep does not need the method list — it reads the slots out
of the vtable — so both now pass and have been removed from the list. Their `_stripped` twins stay:
no symbol table, nothing to sweep.

§24 covers the same classes at the *typeinfo record* level; this is the vtable level. Not done here:
the class struct is not synthesised for a swept class, so there is no `{vfptr}` back-edge to it.

## 26. Bitfields are laid at their containing byte, not as bitfields — open (confirmed 2026-08-25)

**Confirmed open, unchanged, and invisible.** `Materialization.kt:255` still passes
`(offsetBits / 8).toInt()` to `replaceAtOffset`; `ClassBuilder.kt:177` and the base-layout code do
the same division. `insertBitFieldAt` is called nowhere, and `addBitField` still only in
`itanium/Vtable.kt` for the hand-built `__base_class_type_info`.

**No counter in the baselines matches `bit` at all.** This is the only open item where the defect
would destroy a field — the second bitfield overwrites the first — with nothing to report it, on
any of the 24 fixtures. That combination is why it ranks first now, ahead of items with more
visible symptoms. The first step is unchanged and cheap: establish whether any fixture contains a
packed bitfield struct, since if none does, the right move is a detection counter plus a fixture,
not a materialization change.

`Field` (`parse/Ast.kt`) carries `offsetBits`/`sizeBits` faithfully, but every consumer
divides by 8. `fillComposite` (`materialize/Materialization.kt`) ends in
`placeholder.replaceAtOffset((field.offsetBits / 8).toInt(), ft, …)`, so `unsigned a:3;
unsigned b:5;` both resolve to byte offset 0 and the second call overwrites the first: one
field disappears, the survivor gets its declared type's full width rather than its bit width.

Ghidra has `Structure.insertBitFieldAt(byteOffset, byteWidth, bitOffset, dt, bitSize, name,
comment)`. The codebase already calls `addBitField`, but only in `materialize/itanium/Vtable.kt`
for the hand-built `__base_class_type_info` — never for a type parsed from stabs.

Detection is `offsetBits % 8 != 0`, or a `sizeBits` that doesn't match the resolved datatype's
size. The trap is bit numbering: Ghidra's `bitOffset` counts from the least significant bit of
the storage unit, which is not necessarily how the stabs `offsetBits` is anchored — verify
against a fixture on both endiannesses (x86:LE:32 PE, x86-64 ELF are both in the corpus) rather
than deriving it. Check whether any current fixture even contains a packed bitfield struct
before building one.

## 27. Function-scope symbols were attributed by N_SOL, which carries nothing — DONE

The `stale N_SOL?` family (§9's "companion", §17's residual) had one root cause for *locals and
params*, and it isn't recoverable N_SOL tracking: gcc's `dbxout_function_decl` emits the whole
block tree (`dbxout_block`) **after** the function body, and N_SOL is only ever written from
`dbxout_source_file`, driven by line notes. So by the time any local's stab is written, line-note
emission for that function is over: `SymbolRecord.sourceFile` on a function-scope symbol is always
"whichever file the function's *last* N_SLINE was in" and carries zero bits about the symbol. Same
defect 9d812a3 fixed for globals; its closing note ("locals still use sourceFile — those
legitimately migrate to a header when N_SOL says so") was the wrong half. The N_SLINE tagging
itself was already correct (`Harvester.lineSource`) — there was nothing to fix there.

Two lines up in the same gcc function is the signal: *"In dbx format, the syms of a block come
before the N_LBRAC. If nothing is output, we don't need the N_LBRAC, either."* A block's symbols
precede its own N_LBRAC. Measured across the corpus, the next bracket record after a run of locals
is an N_LBRAC **12863/12863** times, never an N_RBRAC. `ScopePairs`' `recordIndex in openRec..recIdx`
was therefore inverted: it could only ever collect a block's *children's* locals, never its own —
which is what the 26k corpus-wide `empty-scope` count was measuring.

**Fix** (`harvest/BlockScopes.kt`): build the real block tree (ownership = the run of records since
the previous bracket), then resolve each block's source from the N_SLINEs its own address range
covers, minus its children's — decl-line match first, else the range's single file, else the
enclosing block, with the function's own source at the root. Bracket addresses now go through
`resolver.stabAddress` like N_SLINEs do (they were assumed function-relative; on the a.out fixtures
33/68 are absolute, so scope comments were landing at `entry + absolute`). `resolveBlocks()` runs
once after harvest and repoints `SymbolRecord.sourceFile`, so importer *and* render read one
answer. Corpus: `empty-scope` 26391 → 6, no other counter moved, full suite green. unpackfile's
inlined locals leave `unpackfile.cpp` for the headers they were compiled from (`Exclusion *__p` →
`stl_vector.h:123`, the allocator locals → `stl_alloc.h:248`).

**Not done — the addressless half.** This only settles symbols that *have* a text address. File-scope
typedefs and class bodies have none, so `Attribution.keyFor`/`multiSourceHeaderHints` still answer
that question separately, and §15 records that unifying them regressed type resolution. Same
principle, but it needs the findByName/collision robustness first. `TypeAst.declSourceFile` remains
raw N_SOL and is right only by luck: block-scoped types are emitted by the same `dbxout_syms` call
as locals (structurally stale), CU-top-level types sit in the opening declaration burst (stale, per
9d812a3), and only types emitted during body output — the template-instantiation typedefs §17 leans
on — genuinely carry their own file. The `body !is Struct && body !is Enum` guard in
`TypeResolver.effectiveSource` is doing that discrimination by proxy.

---

## 28. Collapse inlined regions onto one row, bounded by the block tree — DONE

The decomp body of a .cpp was mostly libstdc++: on unpackfile, **2989 of 6133 body statements (49%)**
carry an N_SLINE naming a header. §5 already folded those into whichever this-file run preceded them,
so they took rows from the code that owns the file *and* borrowed the call site's line tag — the
render showed six consecutive `// ⇐ L 41` rows that were really `basic_string.h`/`stl_list.h` bodies.

**Measured first: the block tree is the wrong instrument for *detecting* foreignness.** Attributing a
line by `func.blockAt(addr).source` finds only **888** of those 2989 (14% of body lines). The two
disagree on 2133 lines and the block answer is a near-strict subset — all but ~32 disagreements are
"N_SLINE says header, block says own file". gcc's block tree is coarse: `main` has 137 SLINE-foreign
statements and *zero* lines landing inside its one foreign block; `FileSystemImage::FileSystemImage`
has 14 foreign blocks covering no decomp line at all. Swapping the SLINE test for the block test —
the obvious reading of "use blockscope" — would have lost 70% of the detection that already worked.

**What the block tree is uniquely good for is *extent*.** N_SLINE says which file each address came
from but draws no boundary: two adjacent inlined calls into the same header are one undivided stretch
of foreign entries. The block bounds them, so they stay two rows instead of merging into one blob.

So: foreignness stays N_SLINE; the region key is the foreign `BlockScope` when gcc bracketed one,
else the contiguous stretch of same-file entries. Then **consecutive inlined regions share one row
however many headers they span** — the reader came for the .cpp, not a row per header. Each region
keeps its own `⇐ header.h L a-b` marker so the row stays traceable, and those go **inline as `/* … */`**:
a trailing `//` would swallow the code of every region after the first. A row reserves one slot in
`spreadBlocks` however many statements it holds — which is what frees the vertical room for this
file's own statements to take a row each. `placeRun` takes a nullable note (an inlined row tags
nothing at the end) and `wrap=false` for those rows, so the condition-wrapper can't re-expand them.
On unpackfile, 482 markers across 4 .cpps, 87 rows carrying two or more. (The marker is no longer a
comment: §36 turned it into a call to a named pseudo-function, on the calling side.)

`BlockScope` gained a `source` constructor property (resolved in `finish`, alongside the per-local
attribution §27 already did) and `blockAt(addr)`; `DecompLine` carries the innermost block covering
*every* address it touches — null when they disagree, so a line straddling a boundary falls back to
the SLINE extent.

**Locals.** Head-fold decls naming a local gcc attributed to a header now drop out — they are declared
in that header's own render (`emitParamsAndLocals` has skipped foreign locals since §27; this is the
decompiler's parallel list finally agreeing). Matched on the base name with Ghidra's `_<n>` dedup
suffix stripped, and only when *every* stabs local of that name is foreign. Corpus-wide **1190 of 1818
stabs locals (65%) are foreign-block-owned**; 878 of 2320 decl lines name a stabs local at all, the
rest being Ghidra temporaries that carry no attribution. unpack's head: 1209 → 939 chars, losing
exactly the `_List_node`/`allocator<char>`/`basic_ios`/`__c1`/`__str` internals.

---

## 32. Layout rewrite — PARTLY LANDED (claim-and-resolve is in; the model and provenance are not)

The `Fragment`/`TargetLine` model and the emit-then-reconcile pass structure are being replaced:
front-positioned `/* L n */` provenance, claim-and-resolve allocation, and no `// stray:` bucket.
Design in [`docs/design-plans/layout-rewrite.md`](../design-plans/layout-rewrite.md). §29's five fixes
were all symptoms of the two decisions that draft removes.

**Audit 2026-08-25 — one of the three shipped.** `render/Claims.kt` exists with a `Claim` type, an
`Owner` priority enum and a resolve pass that "settles contested ones on `Owner` priority, replacing
the retroactive `// stray:` demotion pass" (`FileRenderer.kt:500`), and misattributed claims are
partitioned into `displaced` before anything is written rather than swept afterwards
(`Layout.kt:36`). So claim-and-resolve is the live allocator and the retroactive stray bucket is
gone as a *mechanism* — `// stray:` survives only as the spelling of a demotion the resolver
decides up front.

Not done: `Layout.kt` still defines `Canvas ⊃ TargetLine ⊃ Fragment`, and provenance is still
rendered as a trailing `// ⇐ L NN` rather than a front-positioned `/* L n */`. What is left is the
model swap, which is the large part.

## 29. Decomp placement: the stray sweep ate its own output; rows now anchor to their source line — DONE

Measured on `crypto_mi_test_gcc421.exe` / `xmltest_gcc421.exe` against `corpus/cryptopp` and
`corpus/tinyxml`, which are the fixtures with real source to diff against.

**(a) The stray sweep was demoting decompilation to comments, quadratically.** `FragmentKind.DECOMP`
and `STRAY` both fell through `applyDecompilation`'s sweep to the `else` branch, so every range
re-collected the *previous* range's placed body — and a stray being itself sweepable, it compounded.
Overlapping spans are the norm in a template header, where every instantiation shares one declLine:
`algparam.h` L113 reached **308,384 chars carrying 721 `⇐` tags, 99.9% of it `// stray:`**. Across
cryptopp, **57.6% of all rendered output was stray text**. Both kinds now survive the sweep. Genuine
strays (a type gcc misfiled into a function span, §"vm*_trapset_names") are unaffected — unpackfile
still emits them.

**(b) `spreadBlocks` allocated by size, so drift compounded down a function.** Replaced with
`anchoredBlocks`: a row takes the source line its N_SLINE names, and advances the cursor by **one**
row rather than its height. Its successors are anchored too, so how far it may expand is already
bounded by where the next one lands — that bound is what makes the layout compact where the source
is dense and airy where it is sparse, without a size heuristic. Reserving full height instead (tried
first) only got exact placement to 21.6%: a fat block still pushed everything after it down.

| `.cpp` bodies   | exact     | within ±1 | >5 off | placed *above* their own line | p95 row |
| --------------- | --------- | --------- | ------ | ----------------------------- | ------- |
| cryptopp before | 20.9%     | 47.7%     | 13.7%  | 31.8%                         | 705     |
| cryptopp after  | **69.6%** | **85.6%** | 4.9%   | **0%**                        | 1447    |
| tinyxml before  | 16.1%     | 37.0%     | 10.3%  | 44.9%                         | 198     |
| tinyxml after   | **65.8%** | **78.9%** | 7.7%   | **0%**                        | 297     |

A statement can no longer be placed above the line it came from — a third to a half of rows were.
Total output fell 28% (8.59M → 6.20M chars) and the worst row 308K → 68K, despite the p95 row growing:
dense source lines now cram onto their own line instead of borrowing their neighbours' rows.

**(c) A merged inlined row must still use the rows below it.** First cut reserved *one* row for a whole
stretch of consecutive inlined regions and set `wrap=false`, so `unpackfile.cpp` L42 held 21 regions in
3,720 chars while L43–51 sat empty. The regions now stay separate `DecompLine`s and `placeRun` lays them
one per row up to the next anchor, joining several onto a row only where there genuinely aren't enough —
which is what "collapse consecutive foreign files onto one line" was for. That stretch is now ten rows
of 100–280 chars with no gaps.

**(d) A crammed row keeps its opening statement's indent.** `TargetLine` takes the shallowest fragment,
right when a function opener shares a row with an indented global, wrong inside one crammed run: a
trailing `}` at depth 0 dragged the row to the margin. 35 of unpackfile's 49 longest rows were at column
0; now 27, the rest genuinely opening at depth 0.

*Not* the driver, contra first impression: blank/brace density. cryptopp is 27.0% "free" rows,
tinyxml 34.2%, and tinyxml aligned *worse*; `tinyxmlparser.cpp` has the most free rows of any file and
was second-worst. Decompiler expansion correlates weakly (<1.5 rows per tagged line → 25.9% exact,
≥1.5 → 18.9%); accumulated drift was the real cause.

**(e) Inlined code now renders in the file it was written in, and only there.** It used to render
*only* in the .cpp that inlined it — `atomicity.h` L38 had an N_SLINE address annotation and no code at
all — while dominating the .cpp: unpackfile.cpp was 48 inlined rows against 19 of its own. A second
pass walks the functions whose N_SLINEs name this file and places their regions here; the same
`regionsOf` split answers "what of this function is mine" from either side. A header line is compiled
into every call site, so copies are gathered across all inlining functions at once and identical ones
collapse to one row tagged `×N` — placed per-function, twenty `_M_destroy` copies stacked onto
atomicity.h L38 for 2,510 chars. `Renderer` caches decompilation per function address, so a std::string
method is decompiled once for the whole run rather than once per file that inlines it (runtime
unchanged at ~70s for unpackfile). `placeRun` also drops `subsumedByDecomp` fragments from any row it
writes: the span sweep only reaches this file's own functions, and a header has none, so a line inlined
twenty times had listed twenty N_SLINE addresses.

**(f) Braces balance in every view.** Splitting a body by file breaks it: a decompiled function is one
brace-nested tree with the inlined statements interleaved into the caller's own, so dropping a region
takes with it the `}` closing a block this file opened — unpackfile.cpp went 61/61 → 15/13 and stopped
parsing. Keeping the region's brace-*only* rows overcorrects to 15/59, those being all closers (an
opener rides its statement, `if (x) {`). What works is leaving each dropped region's **net brace
delta** behind: nesting depth is a property of the body, not of any one file, so every view can carry
it. Three cases needed handling — a stretch before the file's first statement (delta goes in front), a
function whose body is *entirely* inlined (`Image::size`, a one-line accessor: no region survives to
hold the closing brace, so one of pure structure is synthesised), and a region placed in the file it
was inlined *from*, which is a slice of someone else's body and closes its own ends. Result: **0 of 55
unbalanced on unpackfile** (52/107 → 11/107 on cryptopp, where the rest are template headers whose
spans genuinely overlap).

**Residual, structural: the function-tail cram.** `unpack` decompiles to ~90 rows and its source span
is 25 lines (L32–56) with two blank rows after it, so whatever the anchors don't absorb piles onto the
last free row — `unpackfile.cpp` L58 is 4,716 chars. No layout rule fixes N rows into M < N slots; the
choices are cram (current), spill past the span and break alignment for everything below, or drop
content. Worth deciding deliberately rather than by accident. Seen again on `xdvimage.cpp` (§37(e)),
where the span is oversubscribed largely because §37(a)'s duplicate bodies compete for it — so fix
that first and measure this again, rather than deciding against a number that is partly noise.

## 30. Unnamed parameters are missing from stabs, and the short list corrupted storage — PARTLY DONE

gcc emits no N_PSYM for an *unnamed* parameter. `HMAC_Base::UncheckedSetKey(const byte*, unsigned int,
const NameValuePairs &)` — third parameter unnamed in cryptopp's source — yields only
`userKey:p(0,449)`, `keylen:p(0,9)`, while the mangled name
`_ZN8CryptoPP9HMAC_Base15UncheckedSetKeyEPKhjRKNS_14NameValuePairsE` still spells all three. Applying
the short list under `DYNAMIC_STORAGE_FORMAL_PARAMS` re-laid every slot and the body decompiled to
`in_stack_0000000c` reads.

`SymbolApplier.padToMangledArity` now extends the N_PSYM list to the demangled arity, typing the
padding from `DemangledDataType.getDataType`. **729 functions** padded on cryptopp;
`in_stack_` artifacts 668 → 598 file-wide, and 8 → 0 in `hmac.cpp`.

**Audit 2026-08-25: padding is in and scaled; the `this` half is untouched and unmeasured.**
`SymbolApplier.padToMangledArity` is live corpus-wide — `degraded-param-unnamed-padded` totals
**5468 across 20 fixtures**, 855 on crypto_mi_test_gcc421_fullstabs (the note's 729 was measured
before the corpus grew). The missing-`this` half has **no counter**: `method-static-no-this` (946
across 15 fixtures) counts §49's deliberate case, not this failure, so nothing distinguishes a
method that correctly has no `this` from one that lost it. Instrument that first — the suspect
below is a guess until a counter separates the two populations.

**Still open: the missing `this`.** 248 of 542 method signatures still render without one, and
`UncheckedSetKey`'s body still treats `userKey` as the object
(`(**(code **)(*(int *)userKey + 0x40))(userKey)`), so its arguments remain shifted by one — padding
fixed the count, not the origin. `ClassBuilder.reparentMethod` parents it into `CryptoPP::HMAC_Base`
(the namespace is right) but never reaches `setCallingConvention("__thiscall")`, while siblings
`Update`/`KeyInnerHash`/`TruncatedFinal` in the same class do get their `this`. The early return at
the `sig !is Method && sig !is FunctionT` guard is the prime suspect — needs its own pass.

---

## 31. Non-returning functions went undetected — DONE

`error()` calls `exit` and never returns, but nothing marked it, so every caller decompiled with the
dead tail still attached. Ghidra's `FindNoReturnFunctionsAnalyzer` ("Non-Returning Functions -
Discovered") misses it twice over: it is a call-site **damage** heuristic and nothing after these call
sites decoded badly, and it runs at `DISASSEMBLY.after().after()`, long before `StabsAnalyzer` at
`LOW_PRIORITY` creates the functions it would examine.

`NoReturnAnalyzer` (`FUNCTION_ANALYZER`, `LOW_PRIORITY.after()`) is Ghidra's own
`targetOnlyCallsNoReturn` walk, ungated: from the entry, over `SimpleBlockModel`, a path may end only
at a call to an already-non-returning function. Iterated to a fixed point via `getCallingFunctions`
so a chain resolves however deep.

**The first attempt was reverted for marking 31 of 41 wrongly, and the cause was not what the revert
note guessed.** It blamed the hand-rolled instruction walk dead-ending on libstdc++'s switch tables.
Moving to the block model does fix that class — an unresolved computed jump becomes a block with no
destinations, which reads as "assume it returns" — but two *specific* clauses turned out to be what
the false positives actually needed:

- **The fall-through past a non-returning call must be dropped.** Ghidra's `setNoFallThru` repair has
  already removed that edge by the time *its* walk runs and has not by the time ours does, so the
  model still offers it — and it points at whatever the linker placed next, which is no part of this
  function. `error` ends at `call exit` with inline string data at 0x401300 behind it, so following
  the edge gets a null block and the walk concludes "returns"; elsewhere the same edge lands in an
  unrelated function and finds its `ret`.

  **The revert note's account of this is wrong and was repeated here for a while.** It said "`error`
  has 13 instructions with a `ret` among them after the `exit` call", making the point that a naive
  "has no `ret`" rule would fire on nothing. `error` is 48 bytes, twelve instructions, and ends *at*
  the `call exit` — gcc emitted no epilogue, correctly, because `exit` is declared `noreturn`. There
  is no dead `ret`. Verified by disassembly; do not reintroduce the claim.
- **A terminal block that tail-calls a returning function returns through it** — Ghidra's
  `if (flowType.isTerminal() && (destFlowType.isCall() || func != null)) return false`, which the
  first port dropped. `std::string::assign` and `std::string::replace` end `jmp <other overload>`
  with their only other exit a `__throw_out_of_range` call, so without it they read as never
  returning. `__gxx_exception_cleanup` (tail-jumps to `__cxa_free_exception`) was the same bug.

Measured on unpackfile: **5 → 32** functions marked. The 27 added are `error`, the `std::__throw_*`
family, `terminate`/`unexpected`, `__cxa_throw`/`rethrow`/`pure_virtual`, `__eprintf` and the CRT
startup entries — all correct.

**Checked across the whole corpus, not one toolchain.** The first sweep covered only 32-bit MinGW PEs
— the case least likely to break — and checked them by grepping for the known bad names, which cannot
catch a false positive spelled anything else. The rosters were then *read* on all 22 fixtures.

Counts are `before → after` (Ghidra alone → with this analyzer), from the two rosters:

| family              | fixtures                                                              | before → after | what gets added                                                                                                                  |
| ------------------- | --------------------------------------------------------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| MinGW PE, cryptopp  | crypto_mi ×4 (3.4.5/4.2.1, ±stripped)                                 | 7…17 → 100…105 | the whole `CryptoPP::` not-implemented base-stub family                                                                          |
| MinGW PE, the rest  | unpackfile, packfile, appquery, xapasmcsr, locale_test ×2, xmltest ×4 | 5…14 → 27…33   | libstdc++ throw/terminate, plus `error` and packfile's `usage`                                                                   |
| ELF x86-64          | box2d_tests 2 → 2, xmltest 6 → 6                                      | **+0**         | nothing: libstdc++ is dynamically linked, so the `__throw_*` helpers are not in the image — only PLT entries, which are external |
| unlinked a.out `.o` | hello, tinyxml, zlib                                                  | 0 → 0          | nothing: no libc linked, so nothing anchors a walk                                                                               |

The two `+0` rows are worth reading as a **coverage gap, not a pass**: on ELF this analyzer has been
shown not to produce false positives, but it has never been shown to do anything there either. A
statically-linked ELF fixture would be the way to exercise it.

**The split is linkage, not platform and not gcc version** — worth stating because the table invites
the opposite conclusion. MinGW has no shared libstdc++, so it links it statically: `unpackfile.exe`
carries 704 `__ZSt`/`__ZNSt` symbols, and `std::__throw_*` / `terminate` / `__cxa_throw` are real
in-image functions this analyzer can walk. Both ELF fixtures declare `NEEDED libstdc++.so.6`
(`box2d_tests` does not link it at all), so those helpers are `UND` and live in the `.so`; what is
in-image is PLT stubs, which Ghidra models as externals and `markNoReturn` skips. ELF gcc is not
avoiding anything — there were no candidates in those two images.

Nor is the dead code at `error()`'s *call sites* a PE artifact: `error()` simply is not declared
`__attribute__((noreturn))` in the source, so gcc emits ordinary fall-through at every call site, as
it would on any target. Recovering exactly that is the point of this analyzer.

The only project-level marks are unpackfile's `error` and packfile's `usage` (prints help, ends
`call _exit`); both were verified in the disassembly and are pinned in `MUST_BE_MARKED`.
`crypto_mi_test_gcc421_fullstabs_stripped` marks 105 — the largest haul — and every `CryptoPP::` entry
is a base-class stub that throws `NotImplemented` (`Clonable::Clone`, `CryptoMaterial::Save`,
`InputRejecting<T>::Put2`, `AllowNonrecoverablePart`, …), plus `SigIllHandler*` which `longjmp`. The
two that read as ordinary accessors are real and really do not return: in `crypto_mi_test_gcc345.exe`
`PowerUpSelfTestInProgressOnThisThread` and `AlgorithmParametersBase::operator=` are each a single
`call __assert` with the next function ~20 bytes later, and the binary's own symbol table gives those
names (an earlier note here guessed the stripped fixture had misattributed them — it had not).

The `DL_SignatureSchemeBase<…>::AllowNonrecoverablePart` forwarders are the interesting case, because
"a virtual call reaching a derived override that returns" is the obvious way this rule could go wrong.
It does not happen here: gcc emitted a *direct* call to `PK_SignatureMessageEncodingMethod::
AllowNonrecoverablePart`, which throws. And the conservative rule covers the other branch by
construction — an unresolved `call eax` yields a block with no destinations, which reads as "assume it
returns".

Zero marks is a legitimate result, so the test's liveness assertion is on function count, not on the
roster being non-empty.

**The gate is narrow by construction and blind outside libstdc++** — it asserts the known regression,
not correctness in general; nothing in it would catch a wrong mark in `CryptoPP::`. The roster written
to `build/test-output/noreturn/` is the artifact for that, and reading it is part of landing a change
here.

**The render win is real but much smaller than the reverted commit claimed.** That commit reported
unpackfile.cpp `goto`/`LAB_` 11 → 2; most of that was the false positives deleting *live* libstdc++
code. Correctly marked, the corpus-wide figure is 45 → 42, and unpackfile.cpp itself does not move.
What does change is local and right: `error()`'s call sites now carry "Subroutine does not return",
their dead inlined-destructor tails are gone, and `unpack` sheds four locals.

**The baseline drift is the same drift, and it is now verified benign.** `text-undisassembled-code`
2 → 30 and `text-data-no-coverage` 227 → 299 (the revert saw 39 / 316). All 30 undisassembled regions
were traced: 24 sit immediately after a call to one of the 32 non-returning functions, and the other
6 are reachable only from those — including two whose sole referrers sit *inside* an already-cleared
region. This is dead code ceasing to be covered, which is the intended effect.

**Only `Mode.AFTER` moves; `CONCURRENT` does not**, and that is measurement order, not the analyzer:
`analyzeDataCoverage` runs inside the stabs import, which in CONCURRENT is at `LOW_PRIORITY` — before
this analyzer's `LOW_PRIORITY.after()` slot has cleared anything.

Corpus-wide, **18 of 24 fixtures drift, and they are exactly the 18 where the analyzer marks
something** — the ELF and a.out fixtures add nothing and do not move. Only `text-data-no-coverage` and
`text-undisassembled-code` shift (`unresolved-symbol-inlined-std` moves on unpackfile alone), always
upward, by 1 to 122. Those two counters now carry an intentional `min` = CONCURRENT, `max` = AFTER
range on each of the 18.

**`-PregenerateBaselines` cannot produce those ranges, and quietly looks like it did.** Both generated
classes for a fixture write the same baseline file, so the two modes race a read-modify-write and a
mode-varying counter is pinned to whichever wrote last — on a full-corpus regen that was CONCURRENT
almost everywhere, reproducing the pre-change values and leaving a *clean git diff* that suggests
nothing drifted. It also drops a counter entirely when the winning mode observes 0, since zero-valued
counters are absent from the map (that is how unpackfile lost `unresolved-symbol-inlined-std`).
`BaselineWriter.write` preserves an existing `min < max` range when the observed value falls inside
it, so the ranges above survive future regens — but the first widening has to be done by hand, from a
plain `-Pmode=AFTER` run's drift report.

`NoReturnFixtureIntegrationTest` runs **one fixture × one setting per invocation** — each is a full
load + autoanalysis — and each writes `build/test-output/noreturn/<fixture>.<on|off>.txt`. **`diff`ing
the two files is the with/without comparison**, so no run pays for both:

- `./gradlew noReturnTest -Pfixture=<file> -PdisableAnalyzers=reachability` — the *before* roster.
  Ghidra's own marks alone; this analyzer never runs, by the pipeline or by hand.
- the same without the flag — the *after* roster, which additionally asserts the analyzer is picked up
  automatically (nothing schedules it, so a broken priority or `canAnalyze` would otherwise leave the
  rest of the assertions passing over Ghidra's marks) and that running it again separately finds
  nothing more.

On unpackfile that diff is 5 → 32, and `error` is one of the 27 added lines.

The libstdc++ gate admits the throw/terminate machinery by name (`__throw`, `terminate`, `unexpected`,
`__cxa`, `_Unwind`) because that machinery genuinely never returns; all 31 of the original false
positives sit outside it.

---
## 34. Brace nesting: balanced but wrongly ordered — DONE

Every earlier check counted `{` against `}`. All three defects here balance by count and nest wrongly,
which is why they survived: **the braces are all present, in the wrong order.**

**1. Balance is not nesting (`braceFix`, `render/Nesting.kt`).** Two sites closed a run by its net
delta — `wrapAsDefinition` for a header's inlined stretches, and the head/body pass for a bodied
function. A stretch beginning `} else {` nets zero and got neither brace, so its `if (…) {` stayed
over in the caller's view; a stretch that closes two blocks and reopens two nets zero the same way and
rendered a function ending before its last statements (xvimage.cpp L473-4, `}}` then `{{`). What
decides both ends is the running depth's **low-water mark**: that many openers are missing in front,
and whatever the run then ends on has to be closed. `Region.balance()` was already dead and is gone.

**2. A region rendered above its own head.** gcc attributes a statement to the line its *expression*
was written on, not the line it executes at, so `__do_find_public_src`'s mask test anchored at the
mask's declaration 170 rows above the function — and `claimsFor` placed it there, `}` and all, before
the `{` that opened it. Body regions are now floored at their function's start.

**3. An opener sorted below its own body — the general case of 2.** Same backwards anchor, but inside
the span, so the floor does not see it. `Integer::IsConvertableToLong` anchored `if (sign ==
POSITIVE) {` at integer.cpp L2805 and both of its branches at L2803; sorting by anchor put the opener
under its branches, so L2802-3 ran inside a block nothing had opened and the `} else {` at L2804 was
orphaned. Backwards anchors are not rare — every loop has one, its condition carrying the `for` line
above the body it follows.

**The decompiler's order is the nesting**, so a body's anchors are clamped to be monotonic in it
(`nestingRows`). The label still names the line gcc gave, so provenance survives the clamp. Since
`allocate` gives an `AFTER` claim the first free row at or after what it asks and works in ascending
ask order, the rows it hands back are strictly increasing — so the rendered order *is* the
decompiler's, and Ghidra's own text is well-nested by construction. That is the guarantee; zero
negative rows is the evidence for it, not the definition of it.

| fixture               | negative-nesting rows | clang brace diagnostics |
| --------------------- | --------------------- | ----------------------- |
| unpackfile            | 2 → **0**             | 4 → **1**               |
| xmltest_gcc345        | 56 → **0**            | 73 → **3**              |
| crypto_mi_test_gcc345 | 52 → **0**            | 83 → **21**             |

Every rendered file now ends at depth 0 and never dips below it. Clang totals move the other way
(349→352, 2611→2989, 2939→3240) for the reason recorded above: an undeclared template makes `<`
ambiguous, so more correctly-emitted scopes manufacture more `expected …`. Judge on the brace column.

**Weaker orders were tried, built out, and measured — they are not enough.** Holding a region below
its *enclosing* opener, and a closing region below what its block holds, covers defects 2 and 3 and
still lets a sibling block invert: an `if (y) {` anchored earlier than the `if (x) { … }` before it
sorts above the lot and ends up wrapping it — balanced, never negative, clauses inverted.

That rule is implemented on the **`nesting-load-bearing`** branch. It matches this one on every
counter readable from the output — negative-nesting rows 0/0/0, clang brace diagnostics 1/3/21 — and
beats it on alignment: mean displacement 5.7/3.2/16.1 against 7.6/13.0/18.9, rows off their line
56/47/54% against 62/58/61%. On the counters, it wins.

It loses on the one measurement the counters cannot make, which is the point of this whole section.
`outOfOrder` (on that branch) counts body regions placed below the running maximum of their
predecessors — 0 here by construction. There: **6,706 across 246 file-renders, 2,646 of them carrying
a brace**, worst file 173 of 387. Each of those 2,646 moves a block opener or closer above something
that preceded it — a block landing around code that was never inside it, balanced and depth-clean the
whole way. The alignment is not worth that.

**What the total order costs, and why it is the floor.** Alignment, charged to the loops: a loop's
condition carries the `for` line, above the body it follows, so a body's tail no longer returns to it.
Mean displacement 2.0→8.7 (unpackfile), 15.4→19.1 (cryptopp); rows off their line 54%→64%. The
visible shape is a run piling below one forward-jumped anchor with that region's own rows left blank
above it — 46/196/199 merged rows have free rows above them, worst 191.

That is not slack left on the table. Two rules bind: a region may not render above the one before it
(this item) and may not render above the line gcc gave it (§29 removed exactly that, a third to a
half of all rows). Together they force `row ≥ max(anchor₁…anchorᵢ)`, which is what `nestingRows`
computes — the pointwise-smallest legal assignment. The blank rows above a pile-up belong to source
lines earlier than the anchor of anything that could fill them, so reclaiming them means breaking one
of the two rules. It is §33's problem (collapse the run), not a placement bug.

**The invariant, per the ask.** `FunctionSpans.closeAnomalies` reports a function whose rendered
nesting has not returned to the level it opened at by the row where the *next* function opens — the
swallowing case, image.cpp's `operator[]` running L41→L128 with three accessors inside it. Printed
per source like `reportAnomalies`; unit-tested in `NestingTest` alongside `braceFix`.

Two things it deliberately does not do, both measured before being cut. It is not asserted against
`spans.closeLine` literally, as the item proposed: a body may borrow the blank rows below its span
and a crammed one closes on its own opener, so ±1 is slack the layout grants, and the literal
assertion reported 67 rows on unpackfile that were almost all that slack. And it does not state the
mirror case — a function closing early over rows of its own still rendered below, which is what
`IsConvertableToLong` looked like. That needs to know which rows are the function's, and rendered
text cannot say: in a header the rows between two openers belong to neither, so reading them as body
reported every crammed one-row function in the corpus (930 of them). Stating it soundly means
carrying the allocator's placements out of `write()`, which is worth doing when something needs it —
fix 3 makes the class it caught structurally impossible rather than merely detectable.

**What is left, and it is not ordering.** cryptopp's 21 are 16 in `algparam.h` plus 2 in `misc.h`,
where the file runs out of rows: `algparam.h` has 72 wrapper groups and 389 lines, so the whole nest
crams onto one 183k-character row. Correctly ordered, correctly balanced, unreadable — that is §33/§5
capacity, not this. The last one on unpackfile is a `do { }` whose `while` was inlined away, which is
a dropped statement rather than a brace.

Two holes the total order does not close, neither of them new. It is per function, so two functions
whose spans overlap still interleave — that is what `closeAnomalies` reports rather than prevents.
And a body that outgrows its span crams onto its ceiling row; if that row is held by a declaration
the claim is *dropped*, taking its braces with it. `FUNCTION_BODY` outranks declarations so a `.cpp`
is safe, but `INLINED_BODY` ranks below them, so a header view can still lose a region that way.

---
## 35. Stop reconstructing what the token tree already knows — DONE

§2 moved *roles* onto tokens and stopped there. Everything structural since had been rebuilt from
rendered characters, and the rebuilds kept failing in the same way.

**Correction to this item's own premise.** It said `DecompilerUtils.toLines` "throws the tree away
before we see it" because it opens with `group.flatten(alltoks)`. That is wrong, and it mis-sized the
work. `ClangTokenGroup.flatten` copies references into a list; it detaches nothing. `ClangLine.addToken`
then sets a *line* parent in addition to the tree parent, and `ClangToken.Parent()` is untouched — so
every token in a `ClangLine` still points into the original tree, and only the line *cutting* is flat.
Replacing `toLines` was never the prerequisite; it buys the cut points, not the tree. Everything below
reads the tree through the lines `toLines` returns.

**What the tree has that the text does not.** `printc.cc`'s `emitBlockIf` wraps each branch in its
own `beginBlock`/`endBlock` — `getBlock(1)` (then) and `getBlock(2)` (else) are separate
`ClangTokenGroup`s. Branch extents are *in the tree*. `if` is emitted `tagOp(KEYWORD_IF, …, op)`, so
the keyword token carries its p-code op. Parens carry real pair ids (`ClangSyntaxToken.getOpen()` /
`getClose()`), so a condition's extent is exact. Braces do **not** — `openBraceIndent` just
`print(brace)`s and its `id` is an indent id, which is why Ghidra's own `getMatchingBrace` walks
tokens; walking *tokens* is still better than counting characters, since a `{` in a string literal is
not a `ClangSyntaxToken`.

**The evidence that text is the wrong substrate.** All three are from §34 and the condition work:

- `uninvertConditions` matched `} else {` because that spelling looked obvious. Ghidra emits `}` and
  `else {` as separate lines (`emitBlockIf` calls `tagLine()` before `KEYWORD_ELSE` unconditionally,
  then `openBraceIndent` with `option_brace_ifelse`, default `Same`). The pass fired 4 times across
  three fixtures and every metric came back byte-identical — inert, not working.
- Its `if \((.*)\) \{` was greedy, and rows carry several statements here (the folded head, rejoined
  continuations). On `… { if (a != false) { if (b == c) {` it spanned from the first `if` to the last
  brace and spliced the negation around two conditions: `if (!(a != false) { if (b`, a paren short.
  Five unit tests passed because they all had one `if` per line.
- `braceFix` and `braceDepths` count `{`/`}` in row text, so a brace inside a string literal
  miscounts. Not yet observed, but not excluded either.

**The API to use, all in `DecompilerUtils` unless noted.** Most of it replaces something we hand-roll:

| ours                                                              | theirs                                                                                                                                                           |
| ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `regionsOf` remapping each line's address through the SLINE table | `getTokens(root, AddressSetView)` — collect the tokens for an address set, built per file from N_SLINE                                                           |
| `braceFix` / `braceDepths` counting characters                    | `getNextBrace(token, forward)` — the *enclosing* brace of a token, so a run's missing openers/closers are asked for, not inferred; `getMatchingBrace`, `isBrace` |
| `Conditions.branchesOf` walking brace depth                       | `ClangTokenGroup` nesting — the branches are the groups                                                                                                          |
| `ifConditionAt` scanning parens back from `{`                     | paren pair ids on `ClangSyntaxToken`                                                                                                                             |
| `THIS_PARAM` / `renameThis()` regexes                             | `isThisParameter(HighVariable, Function)`                                                                                                                        |
| —                                                                 | `isGoToStatement(token)`, `getGoToTargetToken(root, label)` — gotos structurally, for §28-style work and for knowing when a "loop" is one                        |
| —                                                                 | `getFunction(program, ClangFuncNameToken)` — call targets, so `includeClaims` can follow the call graph and not only stabs types                                 |
| —                                                                 | `getDataType(token)`, `getDataTypeTraceForward/Backward(varnode)` — Ghidra's type for a token, to cross-check against the stabs one                              |
| `sjljScaffolding`'s "stack slot written on ≥3 lines" heuristic    | `getVarnodeRef(token)` resolves through the high variable                                                                                                        |

**Sizing.** The blocker is that `DecompLine.text` is the currency of every downstream pass —
`regionsOf`, `dropInlined`, `braceFix`, `wrapAsDefinition`, `Region`, `claimsFor`, `TargetLine`. A
tree-shaped `DecompLine` (keeping `text` for rendering, adding the node it came from) lets them move
one at a time rather than in one cut.

### Done: the row carries its own structure

`DecompLine` keeps `text` for rendering and carries, alongside it, everything the tokens said about
the row as offsets into that text: `braces` (each `{`/`}` with its position), `ifCondition`,
`branches` (the two branches' row ranges), `thisAt`, `booleanCuts` (each `&&`/`||` with its paren
depth), and `memberCuts`. Read once in `compressedDecompLines`, where the tokens are in hand; the
tokens themselves are not kept, so a row stays a plain value, stays unit-testable, and a program's
decompiler markup is not held live behind the render.

Offsets index the *final* text because the spelling substitutions moved to the token — `Renderer.spell`
applies the typedef shortener and the `~`-inside-a-name repair per token, before the row is assembled,
instead of sweeping the finished row.

What each pass reads now:

| was                                                                     | is                                                                                                                                           |
| ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `braceFix`/`dropInlined` counting `{`/`}` in row text                   | the row's brace tokens                                                                                                                       |
| `branchesOf` walking brace depth, `} else {` / `else {` matched as text | the `ClangTokenGroup`s `emitBlockIf` wraps each branch in                                                                                    |
| `ifConditionAt` scanning parens back from `{`                           | the last `if` `ClangOpToken` and its paren pair id                                                                                           |
| `TRAILING_EMPTY_BLOCK` regex splice                                     | the row's last two brace offsets                                                                                                             |
| `THIS_WORD`/`THIS_PARAM` regexes                                        | a `ClangVariableToken` spelled `this`; the parameter's `ClangVariableDecl` extent                                                            |
| `asMemberDefinition` re-parsing `prototypeString`                       | `ClangReturnType`/`ClangVariableDecl` extents cut out of the head; `Function.prototype` assembling the class-body declaration from the model |
| `DESTRUCTOR_NAME` regex                                                 | `Function.getName()` starting with `~`                                                                                                       |
| `topLevelBooleanCuts` scanning for ` && `/`                             |                                                                                                                                              | ` at paren depth | `&&`/` |  | ` operator tokens with the depth from the paren tokens |

**Two shapes the item did not predict**, both found by auditing the group-derived branch pair against
the old brace walk in the same run (9 disagreements on unpackfile, driven to 3):

- The `else`'s brace is not always a sibling of its group. Where `printc.cc` queued a *pending* brace
  to merge an `else if` and then found no `if` to merge with, the brace is printed by the callback
  *inside* the branch group, and the nested `emitBlockIf` closes it inside too — so that group holds
  its own delimiters and its extent has to be unwrapped. A plain `else` is therefore recognised by
  the brace being *somewhere*, and a real chain by its group opening with the `if`.
- The folded head is a row like any other. gcc gives a leading `if` no `ClangStatement`, so it is not
  code by the body test and folds into the head — `b2Free`'s `if` is on row 0. The head had to be
  given the same structure as a body row or its branches were never uninverted.

The 3 residual disagreements are `if`s with empty branches, where neither version does anything.

**Two defects the old text substrate had been hiding**, both fixed by construction:

- `THIS_PARAM` (`^[A-Za-z_][\w:<>,\s]*\*\s*this\s*,?\s*`) matched only a *leading* parameter
  whose type held no `*`. Every `vector<Exclusion*,…> *this` stayed, and so did every `this` sitting
  after a `__return_storage_ptr__`. Cutting the `ClangVariableDecl`'s extent takes it wherever it is.
- A template's constructor is named for the template, not the instantiation, so
  `DynArray<char,10ul>::DynArray` kept a `void` return type.

**Measured against the pre-change render, all six fixtures** (`unpackfile`, `appquery`, `packfile`,
`xapasmcsr`, `xmltest`, `box2d_tests`): statement counts identical, every file's net brace balance
identical, and 573 → 587 `if`/`else` uninversions — the group pairing finds branch pairs the brace
walk missed. Spot-checked against real source: `b2DynamicTree_GetRootBounds` and `b2AllocId` come out
in the order box2d wrote them, where before they were inverted. Every remaining changed line is one
of: a `this` parameter now dropped, a template ctor's return type now dropped, a signature Ghidra
wrapped after the name no longer rejoined as `name (…)`, or a branch pair now uninverted.

### Still open

- `braceDepths`/`closeAnomalies` count `{`/`}` in text. That text is the *final canvas* — skeleton
  rows and decomp rows interleaved, comments spliced in — so the characters genuinely are the
  substrate there, and a `{` in a string literal on a decomp row would still miscount it. Closing it
  means carrying brace counts through `Row` → `Fragment` → `TargetLine`, including the composed head
  row and the pieces `wrapDecompLine` splits a row into. It is a diagnostic, not a render decision.
- `regionsOf` still remaps each line's address through the SLINE table rather than asking
  `getTokens(root, AddressSetView)`. The two answer different questions; the swap is not mechanical.
- Unused from the table: `getNextBrace`/`getMatchingBrace` (the brace list makes them unnecessary
  here), `isGoToStatement`/`getGoToTargetToken`, `getFunction(program, ClangFuncNameToken)`,
  `getDataType`, `getVarnodeRef` for `sjljScaffolding`'s stack-slot heuristic.
- `DecompilerUtils.isThisParameter` is deliberately *not* used: it asks whether Ghidra's model marks
  the parameter an auto-`this`, which is false for any function whose storage we overrode
  (`FileSystemEntry::children`). A `ClangVariableToken` spelled `this` is both exact — `this` is a
  keyword, no other variable can be called it — and complete.
- Remaining regexes in `render/` are all over *names*, never over a rendered row: the `_<n>` Ghidra
  appends to a deduplicated identifier, an array extent in a type spelling, a hex scalar, and the
  path→identifier and path→filename manglings.

---

## 36. Inlined stretches render as calls to a named pseudo-function — DONE; the two sides do not yet agree

§28 left an inlined stretch as `/* ⇐ inlines stl_iterator.h L 633 */`: provenance, but nothing a
reader can follow. It now renders as the call gcc turned into it —
`__inline_basic_string_h_641(local_a8, __pos, __n2);` in the .cpp, against
`void __inline_basic_string_h_641(string * const self, size_t __pos, size_t __n2) { /* inlined into
unpack */` in the header. `self` is the caller's variable, found through storage; `__pos`/`__n2` kept
their stabs names because those locals did not stick in Ghidra.

**The parameter list is gcc's, not a guess.** The first cut derived arguments from p-code dataflow
(`VarFlow`: a variable read inside the stretch whose def is outside is an argument; one written
inside and read after is the result). That works, but the real answer was already in the block tree —
the stretch's lexical block owns the *callee's* variables, under the callee's names, with the storage
they were given in the caller's frame. `stl_construct.h` comes out `__first` in dbx register 0 and
`__last` in 2, which is `_Construct(__first, __last)`. Every foreign block in the corpus owns some:
appquery 563 of 563, sized `{1: 411, 2: 112, 3: 30, 4: 10}`, all `SymbolDecl.Local` — gcc demotes an
inlined function's parameters to `N_LSYM`/`N_RSYM`, so no `Param` record survives inlining, and the
leading locals are the parameters with any tail being the callee's own. Storage is what bridges to
the decompiler: `HighFunction.localSymbolMap` keyed on `HighSymbol.getStorage()` and
`getPCAddress()`, with the stabs name standing in where Ghidra kept nothing there. Dataflow remains
the fallback for stretches gcc bracketed no block for.

**Two filters the dataflow half needed, both found by reading output rather than by reasoning.**

- **`INDIRECT` names every varnode a call might have touched.** Unfiltered, every stretch containing
  a call read the whole frame: `unpack`'s inlined `basic_string` calls came out with the same 30
  arguments each time. Filtered along with `MULTIEQUAL` (the decompiler's phi) and `CAST`.
- **A `HighVariable` need not have a rendered spelling.** The x87 stack came out as `ar1`/`ar3`/`ar4`,
  names that appear in no view of the program. First fix was to keep only names the stretch's own
  statements print; the right fix is `high as? HighLocal` (`HighParam` is one), which drops
  `HighOther` along with `HighGlobal` — a global is in scope wherever the code landed and needs no
  passing — and `HighConstant`. Filtering by type beat filtering by symptom: **42 calls on appquery
  got back arguments the text filter had wrongly stripped**, with no tail either way (max 6).

**`DecompLine.block` is the wrong lookup, for the reason §28 already recorded.** It is the block
covering *every* address its line touches, null wherever they disagree, which §28 measured at 70% of
inlined lines; parameter lists came out empty. Looking the block up by the stretch's first N_SLINE
address instead cut zero-argument calls from ~150 to **21** on both fixtures.

**Open — but the table below needs re-measuring before it is acted on (audit 2026-08-25).** It was
taken before `09069ac` (name inlined stretches from a source root), and `Region.pseudoName`'s own
doc now argues the two sides cannot be made to disagree by the source root, since both read the
same line entries and both ask the same file's real source for the name. `regionsOf` still keys the
caller side on the foreign source (`block?.source ?: entry?.source`), so the structural cause the
note identifies is intact — but whether the 34-of-92 arity agreement still holds is unknown, and
that number is the whole case for changing `regionsOf`. Regenerate before deciding.

**Open: call and definition are derived from different splits, so they disagree.**

| fixture    | names called | defined | both | arity agrees |
| ---------- | ------------ | ------- | ---- | ------------ |
| unpackfile | 198          | 131     | 92   | 34           |
| appquery   | 213          | 138     | 92   | 30           |

`regionsOf` keys the caller side on the foreign `BlockScope` and the header side on the line number —
§28 chose that deliberately, N_SLINE being what detects foreignness and the block only what bounds
it. The consequence is that one stretch has *different extents* seen from the two sides, so
`entries.minOf { addr }` lands in different blocks and the parameter lists diverge; hence also 121
names called but never defined, and names called with two different arities. Making them agree means
both sides deriving the stretch's identity from one key, which is a change to `regionsOf` — the
function §28 and §29 both rest on — and wants measuring the same way. `wrapAsDefinition`'s
`chunkedBy { pseudoName() }` already assumes it.

Not a collision, contra first impression: two callers inlining one header line are the *same* inline
function and should share one definition, and genuine overloads at one line differ in the block's
parameter *types*, so no name-suffixing mechanism is needed.

`wrapAsDefinition` now names its wrapper for the inlined stretch rather than for the inlining
function, which rides along as a comment. Caller-side only: in the header's own view the dropped
regions are the caller's code *around* the stretch, not something that file inlined, so there the
`⇐ inlines` note stays.

---

## 37. `xdvimage.cpp` read end to end: seven defects, ranked by what the reader loses — open

One 180-row decomp view (`appquery`, 130 non-blank rows) read line by line rather than counted. The
counters call this file clean: braces balance, nothing is misplaced above its own line, and the
grammar script's subtracted families hide most of what is wrong with it. Everything below is visible
only by reading the output.

### (a) Aliased copies render two and three times — DONE

`XDVImage::XDVImage(` appears **3×**, `__inline_xdvimage_cpp_30(` **2×**, and source line 36 holds
**8 rows**: 37–40 and 41–44 are the same statements twice over, differing only in Ghidra's local
names (`__ret_4`/`__n_3` against `local_78`). These are gcc's ctor `C1`/`C2` and dtor `D0`/`D1`/`D2`
aliases — one source function, several emitted symbols at the same address range.

§29 already dedups body claims, on `(r.start, head.text)`, and §1 relies on the same idea for
single-line functions. It fails here for the reason §29's own comment half-anticipated: the copies
are decompiled **independently**, so Ghidra numbers their locals per copy and the folded heads
diverge, defeating a key that includes the head verbatim. Keying on something normalised — the head
with local names stripped, or the statement bodies rather than the head — collapses all of it.

**Fixed on both sides.** The head now carries its `prototype` — the signature before the declaration
block was folded in — and the body dedup keys on `(start, prototype)`, which is the identity the decl
block does not carry. Two genuinely distinct functions still cannot collide, the key being their
signatures. The inlined-stretch grouping had the same defect from the other direction: it keyed on the
inlining `Func`, so D0 and D1 each brought a copy of the identical stretch; keyed on the inliner's
*name* they collapse to one tagged `×2`.

appquery, like-for-like: `xdvimage.cpp` 130 → 124 non-blank rows, `vminfo.cpp` 112 → 81,
`image.cpp` 113 → 110, whole render 4241 → 4167, clang errors 803 → 735. Nothing was lost — every
file covers the same set of `⇐ L` source lines before and after, so what went was only the second
copy. (b) is relieved as a side effect on this fixture: the displaced `__inline_xdvimage_cpp_30` was
the D0 copy, and with it gone `has_slt` no longer has a foreign definition inside its braces. (e) is
barely moved (585/516/454 → 585/516/424 characters), so the cram is not the aliases' doing and wants
deciding on its own.

### (b) A stretch is placed inside an unrelated function — DONE

Row 47 carries `/* ⇐ L 30 */ void __inline_xdvimage_cpp_30() { … }` — destructor material — and lands
between `has_slt`'s opening row 45 and the continuation of its body at row 84. A whole foreign
definition sits inside another function's braces.

§29 established that a statement can no longer be placed *above* the line it came from. This is the
same failure downward: a claim anchored at L30 slid 17 rows and crossed a function boundary on the
way. The anchor rule bounds where a row starts, not what it passes through. Claims want barring from
crossing an enclosing function's span, which `FunctionSpans` already knows.

**Fixed as a ceiling, not a rule about crossing.** `FunctionSpans.barrier(line)` is the row before the
next opener below `line`, and every body and inlined-stretch claim now carries it as its
`Claim.limit`; a claim that finds no free row within it crams onto the last one, which is the
allocator's existing answer for a body that outgrows its span. `canvasFree` — `line in 1..maxLine`,
which made the body's borrowed gap the whole rest of the file — is gone, so this is the constraint it
was a placeholder for. `closeAnomalies`, the check for a function still open where the next one
opens, went from 19 across the two fixtures to **0**.

### (c) A file-scope global is emitted inside a function body — DONE

Row 29, `struct __class_type_info_pseudo const _ZTI5Image = …`, sits between the constructor's head
(row 27) and its body (row 30). It is a global whose declLine happens to fall inside the
constructor's span. Nothing checks that a `GLOBAL` claim is not landing inside a `FUNCTION_BODY`'s
braces — the same missing constraint as (b), seen from the declaration side, and probably one fix.

**Not one fix in the end, and not a ceiling.** A declaration is at its line or nowhere, so there is
nothing to clamp: a file-scope global (`enclosingFunction == null`) whose line falls in a function's
interior goes to the displaced appendix under a new reason, `line inside a function body`. A static
gcc really did declare inside a function keeps its place. 34 entries move across the two fixtures,
all but three compiler-generated (`_ZTI*`, `_ZTS*`, `__ioinit`); of the rest, `Bits64 FHA_DEFAULT_TS`
was already displaced as `line already taken` and only the reason changed, and `main.cpp`'s
`vm3_trapset_names` was genuinely being rendered inside `main`'s body at L152 — gcc dates a static
table at the point of use, so the line is the wrong thing about it.

**Cost, and it lands on (e).** Bodies that used to spread into rows below the next function now cram:
appquery 4167 → 4056 rows, unpackfile 2722 → 2675, with the same content (`;` and `{` counts
unchanged per file, and every file covers the same set of `⇐ L` lines). Clang error totals do not
move — 735 and 551 — because a definition nested in a function body is not what the subtracted
families were hiding. So the render is structurally right and tighter, and (e) is now the thing in
the way.

### (d) Member calls still pass `this`, so definitions and call sites disagree

`find_slt(this,uVar1)` ×5, `get_index_in_slt(this,slt_id)` ×3, `has_slt(this,any)` ×1.
`asMemberDefinition` strips Ghidra's explicit this-parameter from *definitions* (the
`invalid parameter name: 'this' is a keyword` family in the grammar section), so the two halves of
the render now contradict each other and neither compiles. The call-site rewrite is the mirror of the
definition one and can read the same `this` token `DecompTokens` already identifies for
`renameThis`.

### (e) The cram, seen on a second fixture

Rows 39, 33 and 34 are **585, 516 and 454 characters**. This is §29's "residual, structural:
function-tail cram" on a file other than `unpackfile`, and the same three choices apply. Note the
coupling to (a): here the span is oversubscribed largely *because* the aliased bodies are competing
for it, so measure this again after (a) before deciding anything.

### (f) 19 rows of displaced/stale tail on a ~150-line file

Four entries claim lines 302–348 in a file that ends near 150 — `__Normal`, `_Trivial`,
`_Is_normal_iterator<…>`, all libstdc++ internals gcc misfiled here — and the rest are
`(line already taken)`. The `stale N_SOL` ones are the file's own activity extent already saying they
do not belong, which is the "Misattributed declarations" work applied to the trailing block rather
than to placement.

### (g) Decompiler artefacts that carry recoverable information

16 `LAB_…`/`goto` rows, and 2 unresolved virtual calls spelled
`(**(code **)(*(int *)this + 8))(this,uVar2,…)`. The vcall is the interesting one: it is a vtable
slot, and the render **declares the vtable type in the same file** (`XDVImage_vftable`), so the
offset can be resolved to the method it calls rather than printed as arithmetic.

---

## 51. `__thiscall` methods that do not take their own class pointer — DONE

14 class methods per fixture came out `__thiscall` with a first parameter typed `undefined4` rather
than a pointer to the class: `__class_type_info::__do_find_public_src`, `ctype<char>` members, and
the rest of the libsupc++/locale surface. Identical count on `appquery`, `packfile` and `unpackfile`
(`xapasmcsr` has none), in AFTER and CONCURRENT alike, none in BEFORE.

**It was not `reparentMethod` — we never touched these functions.** Their signature source is still
`ANALYSIS`, and their classes have no stab body anywhere in the corpus (`ctype<char>` exists only as
the empty `/Demangler/std/ctype<char>` stub; `__class_type_info` not at all). What every offender did
carry is `hasCustomVariableStorage() = true`, with a **non-auto** `this` at `Stack[0x4]` and
`SourceType.USER_DEFINED` — the fingerprint of Ghidra's **Decompiler Parameter ID** analyzer. It
decompiles every function whose signature is still `DEFAULT` (on a C++ binary: every method the stabs
do not describe, already `__thiscall` and class-namespaced from the demangler), the decompiler
reports the this-pointer as an ordinary parameter, that storage cannot match what the convention
assigns, and `HighFunctionDBUtil.commitParamsToDatabase` therefore retries the commit in
`CUSTOM_STORAGE` (its `ParameterImpl(name, dt, storage, program)` is where `USER_DEFINED` comes
from). Custom storage is exactly what stops the convention injecting `this`, so the decompiler's
`undefined4` guess *becomes* the signature. It sits at `DATA_TYPE_PROPOGATION.after().after()`, far
ahead of our `LOW`, which is why CONCURRENT shows the same 14 and BEFORE none.

Fixed by `ThisParamAnalyzer`: for a class-namespaced method with a this-bearing convention, custom
storage and an explicit `this`, re-apply the formals with `DYNAMIC_STORAGE_FORMAL_PARAMS`. That drops
custom storage, and Ghidra re-derives `this` as a pointer to the class — creating the class structure
when the class has none, which is how `__class_type_info` gets one. 16 restored per affected fixture.

An analyzer, not an import pass, because none of it reads the stabs: the damage is the decompiler's
and lands on any C++ program, so this way it also runs where there are no stabs to import, and can be
re-run alone after a Decompiler Parameter ID that re-froze the signatures. It takes the
`AnalysisPriority` slot after the importer, and `StructReturnAnalyzer` moves one further out — its
`correctionFor` skips custom storage, so the repair is what lets it see those methods at all.

Found by folding the former `methodsUseThiscall` — one hand-picked method on one binary — into
`StabsImportRegressionBase.mingwClassMethodsCarryThiscall`, which checks the `this` parameter's type
for every `__thiscall` method.

## 50. Three class-layout invariants that do not hold — DONE

Three defects, and two of the measurements were the test's own fault. Both class assertions paired
an *arbitrary* harvested body with the group winner's Structure, so wherever gcc's CUs disagreed
about a class they reported that disagreement as ours. `builtClasses()` now pairs the winner body
with the type that body built (`index.byLocation`), which is what `fieldsSitAtTheirDeclaredOffsets`
already did.

**(a) A derived class with a non-empty base shows no base subobject — two real causes, one phantom.**

*The pseudo-field detector was half-blind.* gcc emits C++ inheritance as a leading member whose
bitsize is bytes×**64**, and `TypeStore` recognised it by `sizeBits > struct.sizeBytes * 8` — a proxy
that structurally cannot fire for a base small enough to fit inside its own derived class. An *empty*
base is one byte, and every cryptlib policy mixin is empty:
`TwoBases<BlockCipher,Rijndael_Info>` declares `Rijndael_Info` at 64 bits inside a 96-bit struct, so
only the 12-byte `BlockCipher` was ever promoted. The ×64 signature is now taken exactly whenever the
referenced body is in scope (a real field's bitsize is size×8, so ×64 can only be the double
conversion); the size comparison stays the fallback for a Ref the CU never defines. gcc 3.4.5 also
spells the base inline — `BlockCipher:(0,70)=xsBlockCipher:,0,768` — which the `TypeDecl.Ref`-only
guard skipped outright; `InlineDef` now counts too, which is what `PrivateKeyAlgorithm` needed.

*Two bases at the same offset clobbered each other.* `fillStructBases` keyed its resolutions by
offset, so with EBO — `TwoBases` declares both bases at +0 — the empty one arriving second took the
slot the 12-byte one had already claimed, and the merged entry then failed the name check and was
dropped, leaving the class with no inheritance at all. Empty bases are now filtered out up front
(they occupy nothing) and each base is resolved and spliced on its own.

*The phantom:* 16 on `locale_test_customlibstdcxx_stripped` (`basic_stringstream<…>`) and 1 on
`xmltest_gcc345_fullstabs` (`std::fstream`) were the deliberate reserve-as-Undefined1 degradation the
test's own KDoc blesses — read through `components`, which includes Ghidra's autofill, so the bare
reserved bytes presented as own fields at +0. `definedComponents` was the whole fix.

**(b) A single-base class's base field holds an ancestor, not the base.** Not real. cryptopp defines
`InvalidKeyLength` eight times — `Exception` in two CUs, `InvalidArgument` in the other six — and the
32 hits were the two losers' bodies judged against the winner's Structure. Gone with `builtClasses()`.

Behind it, though, was a real one the corpus turned up: on `xmltest_gcc421_fullstabs`,
`basic_ostringstream`'s base field held `basic_ostream<…>.conflict`. `getOrMaterialize` falls back to
a cycle-break stub that [seedPlaceholder] deliberately keeps *out* of the DTM, and splicing one in
makes `replaceAtOffset` resolve it on the way in — forking a `.conflict` twin of a class we had
already built properly. `dtm.contains` now gates the splice: a base we have not actually built is
left as reserved bytes, same as an unresolved one.

**(c) `FillerByteAnalyzer` does not collapse the gas jump-over-fill idiom — DONE.** An unconditional
short jump to the aligned boundary with NOPs behind it (`eb 0d 90…`) is padding, and the Alignment
has to start on the JMP or the jump disassembles as live code in front of it. Two causes, and a third
of the sites turned out not to be padding at all.

*It only looked at the range's leading edge.* gcc parks a dead tail behind the `ret` (`add [esp+4],-4`
on cryptopp), so the `eb 01 90` it wrote for the next function starts mid-range and was never
examined. The analyzer now collects every span in a range rather than one leading run — 7 of 14 on
`crypto_mi_test_gcc421`.

*A linear decode misses one site per mingw binary.* Advancing by decoded instruction length assumes
"next instruction" is meaningful in bytes that are dead by construction, and it is not: on
`appquery`/`packfile`/`unpackfile`/`xapasmcsr` — the same CSR library routine in four builds, so one
site seen four times — the tail reads `… e8 44ceffff  eb c5 │ 3a 28 00 │ eb 0d 90×13`, and the walk
decodes `3a 28` (CMP) then **`00 eb`** (ADD BL,CH), which swallows the JMP opcode and lands on `0d`.
cryptopp escaped it only because its junk (`83 44 24 04 fc`) happens to end flush on the `eb`. The
idiom is now tried at every offset in the range, which costs nothing measurable — the analyzer's
share of a fixture is invisible next to auto-analysis — and is how the assertion finds its own sites,
so the two cannot silently disagree about where a site is.

*The remaining 17 of 17, on `box2d_tests`, are not padding to collapse.* They are `-falign-loops`
fill *inside* live function bodies, where the JMP is reached by fallthrough and is the function's own
control flow; turning it into data would punch a hole through the instruction stream and cost 17
functions their decompilation. `FillerByteAnalyzer` never sees them — it only walks
`getUndefinedRanges`, so bytes already claimed as code are outside its remit by construction — and
`jumpOverFillCollapsedToAlignment` is now scoped to padding between functions to match. box2d, having
no other kind, skips it.

## 49. Static member functions still get a `this` — DONE

`std::locale::global`, `__mt_alloc<char>::_S_get_options` and `__mt_alloc<wchar_t>::_S_get_options`
came out of `locale_test`/`xmltest` gcc-3.4.5 with an injected `this` although their stabs mark them
`?` (static). Their declared parameters survived, so it was never the old `?`-as-pure-virtual
regression.

**It was not us setting `__thiscall` — it was us not unsetting it.** `reparentMethod` already
early-returns on `VirtKind.STATIC`, which is why the three are clean under `-Pmode=BEFORE` and dirty
under `AFTER`: Itanium mangling cannot distinguish a static member from an instance one, so Ghidra's
own demangler pass applies `__thiscall` to both, and Ghidra auto-injects `this` for any this-bearing
convention on a `GhidraClass` member. Not `__thiscall_memret` either — `StructReturnAnalyzer` had
left all three alone; the plain `__thiscall` from the demangler was the whole story. The stabs `?`
flag is the only source that knows, so the static branch now resets the convention to the compiler
spec's default (`hasThisPointer()` gated, so it touches nothing else) before returning.

Found by generalizing the former `staticMemberFunctionTakesNoThis` — which only ever ran on two
non-redistributable fixtures — onto every `STATIC`-flagged method in the harvest.
`StabsImportRegressionBase.staticMethodsTakeNoThis` asserts both halves (declared params survive, no
`this` injected) and now names the convention in its failure message, which is what located this.

## 48. The attribution scorecard — DONE, and it re-grades §44 automatically

§44 was an afternoon of hand-checking against libstdc++ 3.2.3, and item 9 shipped a silent content
loss precisely because nothing repeated it. `render.Scorecard` now computes it: run
`./gradlew probeDump --tests 'ghistabs.render.AttributionProbe' -Pfixture=<binary> -PsourceRoot=<dir>`
and it writes `build/test-output/attribution/<fixture>.txt` — the table, then every item behind it.
Without a root the probe skips and the counters stay silent, so nothing about a rootless run changes.

**Two columns, not one.** The declarations are graded twice, under the attribution the render ships
and under the *base* attribution the root has not touched, so the dump reproduces §44's own table
next to what §46 made of it:

| unpackfile vs `~/git/gcc` @3.2.3 | before root | after root |
| --- | --- | --- |
| with ground truth | 148 | 133 |
| right line (±3) | 82 (55%) | **122 (91%)** |
| right file, wrong line | 4 (2%) | 3 (2%) |
| name absent from the file | 57 (38%) | 8 (6%) |
| past EOF | 5 (3%) | 0 |

Inlines: 177 distinct `(file, line)` stretches, 130 named, **0 unnamed in a file the root mapped**,
47 in files it did not — §45's "the miss rate of the index itself is zero", now a number the build
produces rather than one someone counted.

**It agrees with §44 in shape, not to the decimal, and the gap is the agreement guard.** §44 graded
185 declarations at 63% right-line; the probe grades 148 at 55%. The populations differ by design:
§44 mapped its files by hand, the probe only grades files phase 3 mapped *and* phase 2's agreement
guard kept — and §47 already recorded that the guard drops correct files (`basic_string.tcc` 0-of-17,
`stl_threads.h` 1-of-3) precisely where attribution was worst. So the probe is the stricter of the
two, and it is strict about the same files. The one number that can be compared like-for-like does
match exactly: `source-root-refiled` 250, `source-root-confirms` 75, `source-root-over-hint` 13, as
in §46. Its "126 distinct" is a different distinct: 44 `(name, line)` declarations moved against the
base attribution, one of which (`iterator_traits L122`) moves out of four CUs at once.

**A wrong root is loudly wrong.** unpackfile against a **3.4.6** `libstdc++-v3/{include,config}`
archive instead of 3.2.3:

| | 3.2.3 | 3.4.6 |
| --- | --- | --- |
| sources mapped | 24 of 55 | 17 of 55 |
| stretches named | 130 (100% of mapped) | 33 (32%) |
| right line | 122 (91%) | 10 (19%) |
| `source-root-mismatch` | 10 | **141** |
| declarations re-filed | 44 distinct / 227 | 3 / 29 |

The guard rejects fourteen times as much, the score falls to a fifth, and re-attribution all but
stops: a mismatched tree degrades to *doing nothing*, not to confident wrong answers. That is the
acceptance criterion for the phase and it is met without a code path of its own — the same
per-file agreement check does it.

**Counters alongside the dump**, so a regression is greppable rather than only readable:
`inlines-named` / `inlines-unnamed` /
`inlines-unmapped`, `decl-line-exact` / `decl-line-wrong` / `decl-name-absent` / `decl-past-eof` /
`decl-ungraded` / `decl-reattributed` at INFO, with `inline-unnamed`, `decl-misplaced` and
`decl-moved` itemised at DEBUG. **Nothing computes them during a render** — the probe does, after
the render returns. The plan had `renderAll` tally them so a rootless run reported them too; that
put a measurement on the path of the thing measured, for numbers only the probe reads. (The plan
also called the second counter `decl-file-wrong`; it is renamed,
the file being right by construction — a declaration is graded against the file it was attributed
to, so "wrong file" is not a verdict this can reach.)

**What the 8 remaining misplacements are**, since the itemisation is the point: three are typedefs
gcc dates at the alias rather than the definition (`__string_type` basic_string.h:615, source 962),
five are names the pristine 3.2.3 release does not spell where MinGW's build put them
(`sentry` istream.tcc:211, `_Impl` localefwd.h:311, `basic_string` stringfwd.h:56) — §44's second
kind of unattributable, unchanged and now listed by name every run.

**Not run on xmltest.** `xmltest_gcc421` against the 3.2.3 tree maps 3 of 11 sources and grades
nothing, which is the version guard working rather than a measurement; the 4.2.1 worktree §46 used
is gone, so that baseline is not re-established here.

---

## 47. An included file's extent is the file's length — DONE, and inert on today's corpus

§43's extent for an included file is measured by the declarations it is judging, which is circular.
Where `--source-root` maps the file and phase 2's agreement guard keeps it, the file's length is a
fact instead: `FileRenderer.activityExtent` and `ownExtent` take `DeclaratorIndex.lineCount` ahead of
the estimate. A **CU** keeps the code-derived extent — a `.cpp`'s real length is no evidence about
which of *its* declarations gcc misfiled, and that is the whole of §38.

**Measured, and it changes nothing anywhere.** unpackfile (24 of 55 sources mapped), appquery (26 of
66) and xmltest against 4.2.1 (30 of 126) render byte-identically with and without the change, root
or no root. The reason is worth stating rather than filing as a null result: on every mapped file the
real length is *longer* than the estimate — `stl_uninitialized.h` 290 vs 215, `stl_algobase.h` 820 vs
540, `char_traits.h` 252 vs 147 — so the extent only ever loosens, and nothing lands in the range it
gains. **§46 emptied the residue first.** The declarations that used to sit past a file's reach are
the ones the root re-filed a phase earlier, so by the time the length is available there is nothing
left for it to displace: `stl_uninitialized.h`'s four typedefs at L426–750 are stale by arithmetic
against 290 lines, but they are no longer in that file to be judged.

What the phase buys, then, is not rows but the retirement of a heuristic: where the root knows the
file, a declaration can no longer vouch for its own file's extent, and §43's gap statistic is not the
plan there.

**The wrong-length hazard is real and the guard caught it.** A short wrong length would displace real
declarations, so the length is refused where *code* contradicts it — an N_SLINE or a function body
past EOF is address-backed, and a declaration past EOF deliberately counts for nothing, being the
thing under judgement. One file in the corpus trips it: xmltest's MinGW `stdio.h` maps to a 4-line
`stdio.h` in the gcc tree while its N_SLINEs reach L553, reported as `source-length-conflict` and
refused. Exactly one file, exactly the predicted shape.

**Two of the phase's own acceptance criteria are answered by the agreement guard, not by length.**
`stl_threads.h` (`class _STL_auto_lock` at L233, file is 236) and `basic_string.tcc` get no length at
all: the guard scores them 1-of-3 and 0-of-17 and drops them. Both are the *right* files — what they
are judged on is the base attribution, and their claims are precisely the libstdc++ declarations gcc
misfiled, which §46 moves and the guard cannot see. That is the cost of the anti-circularity rule in
§46 (the guard must not consult the root it validates), and it is where a second look would pay:
the files whose attribution was worst are the files denied the fact that would fix them.

---

## 46. A misfiled declaration renders in the file that declares it — DONE

§44 found that gcc keeps the line and loses the file: of 48 distinct misfiled declarations, 24 name a
file that declares them at the very same line number. With a source root the file is knowable, so
`HarvestIndex.effectiveSourceFor` gains one input — the local file whose text declares that name at
that line, accepted only when exactly one does. No new path through the render: attribution has had a
single accessor since §15/§27, and this is one more thing it consults.

**unpackfile against `~/git/gcc` at 3.2.3: 81 distinct `(name, line)` declarations re-filed**, 250
instance moves, 75 places where the root confirms the file gcc recorded, 13 where it overrules a
hint. Rows 3,188 → 2,965 (−7%), same 54 files, displaced 32 → 28. What moved is exactly the shape
§44 predicted — the project's own headers shedding libstdc++ declarations, the stdlib headers taking
them back:

| file | rows |
| --- | --- |
| `image.h` | 32 → **7** |
| `filesystemimage.h` | 154 → 89 |
| `xvimage.h` | 59 → 21 |
| `basic_string.tcc` | 95 → 79 |
| `stl_alloc.h` | 126 → **135** |

`image.h` at 7 rows is the priority-1 item at the top of this file ("25 rows of its own, 31 of
libstdc++, spread over 908 lines") — its libstdc++ rows are gone because they were never its.

**All four of §44's named cases move**, and each lands on the line the 3.2.3 source has it on:
`_Is_POD` basic_string.h:111 → stl_uninitialized.h, `__Normal` → stl_algobase.h, `_Vector_alloc_base`
stl_algobase.h:79 → stl_vector.h (L79 is `class _Vector_alloc_base {`), `rebind` basic_string.tcc:662
→ stl_alloc.h. **And §43's four impossible typedefs are answered rather than held out**: `_Trivial`
L426 and `__Normal` L448 are stl_algobase.h's, `_Tag` L733 and `_Integral` L750 are basic_string.h's.

Three things the plan did not have, all from measuring:

- **The root goes *before* the hint, not after.** The plan put the hint first, its vote being code
  rather than inference. They disagree three times on unpackfile, all `_Vector_alloc_base<…>` L79,
  and the hint is wrong every time: it names stl_iterator.h and stl_algobase.h, whose only claim is
  that the instantiation's methods compiled there, while stl_vector.h L79 *is* the class. On xmltest
  the same reversal moves 487 locale facets out of `locale_facets.tcc` into `locale_facets.h`, where
  `class time_put` is at L3399. A definition at the line beats a vote about where the code went.
- **A forward declaration is not a declaration site.** With `class X;` counted, `stringfwd.h` L49's
  `class allocator;` outranked `stl_alloc.h`, where the class is — the one case where the hint was
  right and the root wrong. Excluding them removes it, and is what makes the reversal above safe.
- **±1 on the line, and it is not slack.** gcc dates a declaration at its body's opening brace and
  the index records the name's line, so libstdc++'s brace-on-the-next-line style puts them one apart
  — `struct _Alloc_traits` is L897 and gcc says 898. Exact-line matching found 55 declarations;
  ±1 finds 81, and the 26 it adds include the whole `_Alloc_traits<…>` L898 family, which §43 called
  a grade-3 wall ("its home is stl_alloc.h, which holds no instantiation of it at all, so no vote or
  sibling can reach it"), plus `__simple_alloc` L231, `allocator<T>` L649, `list<FileSystemEntry>`
  L291 and `vector<short unsigned int>` L167 — every one checked against the 3.2.3 source and right.

**appquery**: 288 instance moves, rows 3,650 → 3,509, and the same shape (`image.h` 33 → 7,
`xvimage.h` 56 → 20, `vminfo.h` 69 → 37; `stl_algobase.h` 55 → 69, `stl_function.h` 2 → 15).
**xmltest** against a 4.2.1 worktree: 2,357 moves, 26,046 → 25,599 rows, and the guard rejects 118
files — a build tree is not the release tree, and being told so is the guard working.

**No declaration can move into a file that does not declare it**, because the query *is* the
condition: `declarers(name, line)` returns the file whose text has it. Nothing was lost either —
comparing the set of declaration texts across the whole render, unpackfile drops four, and all four
are forward-declaration stubs now listed in the instantiation appendix of the file they belong to
(`type_traits.h`, `stl_algobase.h`, `stl_iterator_base_types.h`) instead of standing in `image.cpp`.

Without a root the render is byte-identical to before. The full §44 re-grade is not recomputed here:
it would re-derive by the same rule that made the moves and so cannot disagree with them — grading
what the root did *not* reach is the scorecard's job, and the scorecard is its own phase.

---

## 45. Inlined stretches carry the name of the function they came from — DONE

§44's cheapest readability win, taken. With `--source-root`, `__inline_stl_vector_h_123` renders
`_M_deallocate__stl_vector_h_123`: the declarator index (§ phase 4) is asked what definition encloses
the stretch's first line in the real file the source root resolved, and the answer becomes the first
half of the identifier. The line stays in it — two stretches of one function inlined from different
lines are different code, and `_M_deallocate` alone would name both — and the *call* in the .cpp and
the *definition* in the header compute the identifier from the same `(file, lo, hi)`, so §36's
navigability property holds by construction rather than by care.

**unpackfile against `~/git/gcc` at 3.2.3: 163 of 227 distinct stretches named.** Of the 195 that name
a libstdc++ file, 163 (84%) are named, and **every stretch in a file the root actually mapped is
named — the miss rate of the index itself is zero.** The 64 left are exactly the files phase 3
cannot map, and they divide as:

| left `__inline_` | why |
| --- | --- |
| 31 | `filesystemimage.h`, `xvimage.h` — proprietary, no source in any root |
| 19 | `<fstream>`, `<ostream>`, `<istream>`, `<iostream>`, `<iomanip>`, `<new>` — a *source* checkout ships these as `include/std/std_fstream.h` and the install renames them, so no path or filename rule bridges it |
| 13 | `atomicity.h`, `gthr-default.h` — the `mingw32/bits/` directory phase 3 reports ambiguous across 16 `config/cpu/<arch>/bits` |
| 1 | `ctype.h` — MinGW's C header, not in a gcc tree |

So the 90% acceptance figure is a statement about *phase 3's mapping*, not about naming, and the two
gaps above are what would move it. Both are known and neither is fuzzy-matchable: the first wants the
`std_<name>.h` → `<name>` install rename, the second wants evidence of which architecture's
`atomicity.h` was compiled in.

**Heads gained parameter lists too**: 99 stretch definitions rendered `void f() {` before, 50 after —
49 heads now carry the source's own list (`_Construct(_T1* __p, const _T2& __value)`) where gcc's
lexical block held no locals to derive one from. Where the block *does* hold them they win: those are
the instantiated types (`Exclusion *`, not `_ForwardIterator`) under the same names gcc took from the
source anyway, and they are what the pseudo-call passes arguments for — substituting the source list
wholesale would let head and call disagree on arity, which is the property that makes the two views
read as one function.

**Ten names checked by hand against the 3.2.3 sources**, all right, including the shapes §44's Python
could not do: `allocator__stl_alloc_h_664` (`allocator() throw() {}`, a one-line body),
`dtor_vector__stl_vector_h_375` (`~vector()`), `operator___stl_iterator_h_726` (an `operator-` whose
head spans three lines), `_Alloc_hider__basic_string_h_208`, `_List_iterator__stl_list_h_126`.

**Nothing else moved.** Without a root the output is byte-identical to the previous commit's across
four renders (unpackfile and appquery × skeleton and decomp). With one, every one of the 54 files
becomes identical to the no-root render once the names are renamed back and the gained parameter
lists are erased — the root changes the identifiers and those lists, and nothing else.

One thing did have to change for the off path to stay inert: the empty-block splice in `Layout`
matched `__inline_\w+\(`, which a named stretch no longer is. It now matches the shape both
spellings share — a `__` join and the source line the name ends with — because `FUN_00401234()` ends
in digits and `__cxa_end_catch()` has the join, and either one alone would splice a real call into a
block it does not belong in.

---

## 44. What the render attributes, graded against libstdc++ 3.2.3 itself — measurement

unpackfile links MinGW's libstdc++ **3.2.3**, and gcc's tree is a clone at `~/git/gcc`, so
`git archive releases/gcc-3.2.3 libstdc++-v3/{include,src,libsupc++,config}` gives the actual headers
the compiler read. Every attribution the render makes can therefore be checked rather than argued
about. (Two mapping traps: the installed `<iostream>` is `include/std/std_iostream.h`, `atomicity.h`
is `config/cpu/i486/bits/`, `basic_file.h` is `config/io/basic_file_stdio.h`; and `include/c_shadow/`
holds shims named `stdlib.h`/`stdio.h` that are *not* MinGW's C headers — mistake those for ground
truth and seven declarations look impossible when nothing is known about them at all.)

**Inlined stretches: sound, and nameable.** 766 marker occurrences, 217 distinct `(file, line-range)`.
374 name project sources, which gcc's tree says nothing about. Of the 392 that name a libstdc++ file,
**every one lands on real code — zero past EOF, zero on a blank or a comment** — and 368 (94%) land
inside a function definition whose name can be read straight off the source:

| | | |
| --- | --- | --- |
| `stl_vector.h L123` ×23 | → | `_M_deallocate` |
| `stl_iterator.h L584` ×18 | → | `inserter` |
| `basic_string.h L229` ×17 | → | `_M_data` |
| `stl_uninitialized.h L109` ×16 | → | `uninitialized_copy` |
| `atomicity.h L38` ×7 | → | `__exchange_and_add` |

The remaining 24 land on one-line bodies (`allocator() throw() {}`, `operator new`,
`bool operator()(…) const`) that a "find the declarator head above" scan doesn't count as a head —
right line, no name. So §28's region split and §36's `__inline_<file>_<line>` naming are confirmed
against the source, and **an optional source root would let those pseudo-functions carry their real
names** (`__inline_stl_vector_h_123` → `vector<T>::_M_deallocate`), which is the single cheapest
readability win visible from here. **Done in §45** — and the 24 one-line bodies are named there too,
which is where the 94% became 100% of what the root maps.

**Declarations: two thirds right, and half of the rest are recoverable.** 332 tagged declarations,
185 with libstdc++ ground truth:

| verdict | count | |
| --- | --- | --- |
| right line (±3) | 117 | 63% |
| right file, wrong line | 10 | 5% |
| name absent from the claimed file | 54 | 29% |
| past EOF | 4 | 2% |

The 4 past-EOF are stl_uninitialized.h's `_Trivial`/`__Normal`/`_Tag`/`_Integral` at L426–750 in a
291-line file — the ones §43's conflict rule already holds out, now confirmed impossible rather than
merely suspected.

**The important half: of the 48 distinct misfiled declarations, 24 name a file that declares them at
the very same line number.** `_Is_POD` claimed at basic_string.h:111 is stl_uninitialized.h:**111**;
`__Normal` at basic_string.h:322 is stl_algobase.h:**322**; `_Vector_alloc_base` at stl_algobase.h:79
is stl_vector.h:**79**; `rebind` at basic_string.tcc:662 is stl_alloc.h:**661**. **gcc kept the line
and lost only the file** — exactly what §38 found in `dbxout_prepare_symbol`, now visible as a
statistical regularity rather than an inference from one case. It also says what a re-attribution
pass would need: not a better line, a better *file*, and the line is the key to search on. **Done in
§46**, which moves 81 distinct declarations rather than 24 — the line needs ±1, because gcc dates a
declaration at its opening brace.

The 24 that stay unattributable are of two kinds: stab-level names with no textual counterpart in the
source (`_Trivial`, `_Value_type`, `_Has_trivial_destructor`, `_Distance` — the compiler's own names
for member typedefs it instantiated), and `<limits>`'s `_iec559_consts`/`_rep`, which appear nowhere
in the 3.2.3 tree because MinGW ships a patched `<limits>`. The second kind is a reminder that
"absent from the pristine release" is not the same as "misattributed".

---

## 43. `activityExtent`'s header proxy — DONE, and the half it was standing in for is not

`activityExtent` runs two regimes — a CU measured by its code alone, an included file by its
declarations — and picked between them on `spans.ranges.isEmpty()`. That is not the question: a
header of inline methods has spans (`filesystemimage.h`) and a CU whose functions were all inlined
away has none. **gcc says which it is**: an `N_SO` is a translation unit, everything else was
included, and `SourceFile.CUSource` has carried that since the parser. `HarvestIndex.compilationUnits`
exposes it (folded, like every other source key) and the `when` asks that instead.

**On its own that trades three right answers for five.** The five headers with inline methods were
taking the CU path, so their own late declarations were being called stale — `class _STL_auto_lock`
at stl_threads.h L233, `class rebind<char>` at basic_string.tcc L662, `list<FileSystemEntry>` at
filesystemimage.h L291 all render in place now, correctly. But the same accident was displacing four
instantiation typedefs in stl_uninitialized.h (`_Trivial` L426, `__Normal` L448, `_Tag` L733,
`_Integral` L750, in a file gcc 3.x ships at ~300 lines) and one in stl_list.h, and those really are
misfiled.

**So the conflict rule was extended to reach them.** `_Trivial` carries L426 in *both* basic_string.h
and stl_uninitialized.h, `_Tag` L733 in both stl_list.h and stl_uninitialized.h — the same fact
`conflictedTemplateDecls` already records for `_Alloc_traits<…>` at L898, in a different shape. There
is now a `conflictedTypedefDecls` alongside it and `misfiled` consults whichever fits the declaration.
Tags and typedefs are counted **separately** because one namespace makes `class fpos<int>` conflict
with a `fpos` typedef and `class string` with the `string` one, which cost stringfwd.h its `class
string` and `<limits>` its `numeric_limits` specialisations when it was tried.

Net against the pre-change render: unpackfile 6 files, three declarations recovered and none lost;
appquery 6 files, three recovered against stl_uninitialized.h's four typedefs, which this fixture
does *not* catch — see below. Everything else that moved is the reason string on an
already-displaced row (`stale N_SOL` → `this line is claimed by several files`).

**Measured again on xmltest (gcc 4.2.1 mingw, full stabs), where it matters far more.** The two PE
fixtures understated this: xmltest has 44 files change, not six, and they are almost all libstdc++
**translation units** — the other leak direction. A `.cc` whose functions were all inlined or never
linked has no spans, so the old proxy called it a header and let its declarations set their own
extent: `ext-inst.cc` rendered **821 rows** for a unit with no code at all, every row a libc typedef
or class gcc's N_SOL had dumped into it at header line numbers. Whole render **37,256 → 24,183 rows
(−35%)**, and tinyxml's own five files are byte-identical.

**It also exposed a defect in the change, since fixed.** With the CU rule, such a unit's extent is 0,
every declaration is stale, `maxLine` is 0 — and `render()` returned at its "nothing sits on a line"
guard *before the claim passes ran*, so those declarations never reached the displaced appendix
either. 19 files vanished and **71 types and 80 typedefs** (`_Rope_*`, `_Setw`, `crope`,
`_Refcount_Base`) disappeared from the render without a word — the same silent-loss trap §38 records
for `maxLine` gating. The guard now runs the three declaration passes and displaces them: 123 files
again, 0 typedefs and 0 types lost, appendix 1,420 → 8,725 entries, which is what a CU of unplaceable
declarations honestly is. No effect on unpackfile or appquery (neither has a file that reaches the
guard).

**Graded against the real headers on unpackfile.** gcc's own tree is a clone at `~/git/gcc`, and the
fixture's libstdc++ is **3.2.3** exactly, so `git show releases/gcc-3.2.3:…` settles each of the three
declarations this item moves rather than leaving them to judgement:

| declaration | claimed at | ground truth | verdict |
| --- | --- | --- | --- |
| `class _STL_auto_lock` | stl_threads.h L233 | file is 236 lines; that class's body ends at L232 | **right** — was displaced, now in place |
| `class rebind<char>` | basic_string.tcc L662 | that line is inside `basic_string::copy`; `struct rebind` is **stl_alloc.h L661** | **wrong** — was displaced, now in place |
| `class list<FileSystemEntry>` | filesystemimage.h L291 | proprietary header, no source; its own content stops at L147 | suspicious |

So on unpackfile the item is a wash: one right, one wrong, one doubtful, four impossible typedefs held
out by the conflict rule, and everything else a reason string. Skeleton 2,856 → 2,853 rows, decomp
3,128 → 3,188 (filesystemimage.h's canvas grows with the L291 claim, which un-crams its inlined
bodies — a readability gain resting on a line that is probably a lie). Nothing gained, nothing lost.
The value of the item is entirely in the CU direction xmltest shows.

**And it tells the gap rule what it must do**, since the same three cases now have known answers.
Content lines per file, in order: stl_threads.h 67, 164…211, **233** (gap 22 against an existing gap
of 97 — not an outlier, stays, correct); filesystemimage.h 135…147, **291** (gap 144 against gaps of
2 — outlier, goes, correct); basic_string.tcc 536…622, **662** (gap 40 against gaps up to 43 — *not*
an outlier, stays, wrong). Two of three, and the one it misses is the one where gcc's line belongs to
a different file of similar length. That is the honest ceiling for a gap statistic, and worth knowing
before building it.

**What is left, stated precisely.** For an included file every bound available is circular: it is
measured by the declarations it is judging. Two blunter rules were written and measured before
settling:

- *Any template instantiation past the file's reach is misfiled* — gcc does file those by accident.
  It also empties the headers whose whole content is templates: `type_traits.h` lost all twenty
  `__type_traits<…>`, `stringfwd.h` its `class string`, `<limits>` its specialisations.
- *Excluding disputed declarations from the file's own reach* — necessary (a declaration must not
  vouch for itself) but not sufficient, and it is what the first rule collapses through.

The residue is exactly that insufficiency: in appquery, `_Integral` L750 happens to be claimed by no
other file, so it vouches for stl_uninitialized.h reaching L750 and its three conflicted siblings sit
inside that. The signal the note originally guessed at — distance — is the right one, and the shape
it needs is a **gap**, not a threshold on lines: `class XVImage` sits 4 lines past attested code
among evidence spaced 2–10 apart, while stl_uninitialized.h's evidence stops at ~300 and resumes at
426. Cut the file at the first outsized gap and all four go; `type_traits.h`, evenly spaced
throughout, keeps everything. That wants its own pass, with the gap statistic measured across the
corpus rather than picked.

**The gap statistic is not the plan where a root exists — §47 replaced the estimate with the file's
length.** An included file the root maps and the guard keeps is not measured by its declarations at
all: `stl_uninitialized.h` is 290 lines, so a typedef at L426 is stale by arithmetic. The two blunt
rules above stay recorded as measured and rejected, and the gap statistic stays the only signal for
the no-root path and for the files no root maps.

**With a source root, three quarters of that is no longer the question** (§46). The four impossible
typedefs are not "past this file's reach" — they are *in another file*, and the root says which:
`_Trivial` L426 and `__Normal` L448 are stl_algobase.h L426 and L448, `_Tag` L733 and `_Integral`
L750 are basic_string.h L733 and L750, each confirmed by the line in the 3.2.3 source. They are
placed rather than held out, and the conflict rule stops seeing them at all, because once every
claimant of a `(name, line)` is moved to the one file that declares it, the pair is no longer
disputed.

What stays open is the same thing it always was, now scoped: **the no-root path**, where the gap
statistic is still the only available signal, and files no root maps (proprietary headers, the
`<fstream>` group, the ambiguous `mingw32/bits/`) — which is where the circularity still bites and
where a gap pass would still earn its keep.

---

## 42. The last inline markers sat outside the block they emptied — DONE

§28's marker goes *inside* the block whose content was inlined away, so `for (…) { /* ⇐ inlines
stl_vector.h L 123 */ }` says the body is over there rather than showing an empty block with a
footnote. `dropInlined.flush` does that splice on the row it is folding onto, and can only do it when
that row already carries both braces — which is where the leftovers came from: a `{` and its `}` that
reach the row from *different* fragments (separate claims, or separate `DecompLine`s crammed together
by `fitRows`) are still two strings when `dropInlined` runs, and the marker lands after the closer.

Fixed one level down, at the only point where a row is whole: `TargetLine.render` splices an empty
block's trailing markers between its braces after joining the fragments' code. Text-level by
necessity — a `Fragment` carries code as a string, the tokens are three passes upstream — but bounded
to the two spellings a marker has, the `/* ⇐ inlines … */` note and the `__inline_…()` pseudo-call, so
Ghidra's own empty loop with an unrelated statement after it is untouched.

A/B on unpackfile with the splice off and on: **5 rows, in two files, and nothing else in the render
moves** (`stl_construct.h`, `stl_iterator.h` — the header views, where a stretch's braces come from
`wrapAsDefinition`/`braceFix` rather than from a statement). The closer moves to the end of the marker
run, so brace counts are unchanged. Pinned by `LayoutTest`, which covers both spellings and the
untouched `{ }`.

---

## 41. Unbound demangler stubs — reframed: a corpus-wide number, still untriaged

**Audit 2026-08-25.** The premise ("one fixture entered the corpus red") is no longer the shape of
this. Since it was written the binding machinery was reworked four times — `64fab79` bind across
the builtin-spelling split, `476a00b` spell type names the way Ghidra's demangler does, `5e79670`
retarget the signature sites an unbindable stub reached, `6a7b73f` bind a bare stub only when the
binary instantiates it once — the test moved to `audit/DemanglerWhitelistAuditTest.kt`, and
`5531cf0` pruned the whitelist. `DemanglerWhitelist.ALLOWED` still contains **no CryptoPP entry**.

It is now baselined rather than asserted-to-zero, so the number is visible everywhere:
`demangler-unbound-stub` totals **840–841 across 19 fixtures** — crypto_mi_test_gcc421 102,
xapasmcsr 66, packfile 65, appquery 64, unpackfile 62, and the fixture this section is about,
`crypto_mi_test_gcc421_fullstabs_stripped`, at **43**. Against it, `demangler-exact-match` reaches
808 on crypto_mi_test_gcc421_fullstabs, and `demangler-unbound-stub-signature-site` 1795–1797 says
what those stubs still reach.

Two cautions on those totals. They are sums over fixtures of a per-fixture *range*: baselines carry
`min`/`max` across run modes, and `crypto_mi_test_gcc421_stripped` is genuinely mode-dependent here
(`demangler-unbound-stub` 42..43, `…-signature-site` 74..76), which is where the slack in both
totals comes from. Every per-fixture figure quoted above is a point snapshot (`min == max`). And 43
is **not** "42 plus one": the 42 in the note below was produced by a different demangler, so the two
are not a before/after pair — only the triage question carries over.

The original question is unchanged and still unanswered — **inherent, or a materialization gap** —
but it is now a corpus-wide triage rather than a whitelist decision about one binary, and the
fullstabs/stripped pairs are the lever: a stub that binds on `…_fullstabs` and not on
`…_fullstabs_stripped` is a symbol-table dependency, not an inherent one.

Original note, as written:

`crypto_mi_test_gcc421_fullstabs_stripped.exe` yields **42 empty `/Demangler/CryptoPP/*` stubs**
(`AbstractGroup`, `AlgorithmImpl`, `BlockCipherFinal`, …) and `DemanglerWhitelist.ALLOWED` contains
**no CryptoPP entry at all**. The dates settle it: the whitelist was last written 2026-07-30
(`b56bd2e`), the fixture was committed 2026-08-07 (`61a5aa0`, 49 commits later). It entered the
corpus with 42 untriaged stubs and the test has been red ever since — no code change caused it.

Which of the two things it is has not been decided:

- **Inherent**, like the rest of the whitelist — a stub the demangler names from a mangled symbol
  that this binary only forward-declares, with no full class stab to bind to. Then whitelist them.
- **A real materialization gap.** The fixture is *fullstabs*-stripped: full stabs, stripped symbol
  table. If the CryptoPP classes do have complete stabs, 42 of them failing to bind to their
  demangler stubs is the gap the test exists to catch, and whitelisting would bury it.

Read a few of the 42 against the stabs before choosing.

**Method note, because it cost a bisect.** Fixture binaries are tracked but were all added in one
`commit binary fixtures`, so copying one into an older worktree to bisect *manufactures* the failure
at commits where that fixture was never part of the corpus. The three "it fails here too" results
that pointed away from this session's changes were right about the conclusion and worthless as
evidence. Check when a fixture entered the corpus before bisecting a fixture-specific failure.

---

## 40. The render is not reproducible under load — the silent half is DONE

**Audit 2026-08-25.** The part the note called the one that matters more is in:
`Renderer.decompile` records every function Ghidra did not finish in `undecompiled`, and
`FileRenderer.kt:442` renders `, decompilation did not finish` on it, so a reader can now tell an
empty function from one Ghidra gave up on. `DECOMPILE_SECONDS` is still **30**, so the underlying
non-determinism is unchanged — but it is now a visible difference between two renders rather than
a silent one, which is what made it cost an hour of bisecting.

Left: decide whether 30 s is the budget. Note the timeout is also the reason a diff of two renders
is not by itself evidence about a change — check `undecompiled` before concluding anything from one.

Original note, as written:

`Renderer.decompile` gives Ghidra 30 seconds per function
(`decompileFunction(ghFunc, 30, …)`). `xmltest.cpp`'s `main` — hundreds of locals — sits on that
boundary: it decompiled in three runs this session and timed out in three others, on the same commit,
differing only in what else the machine was doing. When it times out the body claim never exists, so
the file silently falls back to the skeleton's `int main(…) {  /* L 303 — opens main */` and every
row of that function's code is absent.

It cost an hour of bisecting an attribution change that turned out to be innocent (§38's marker
widening), and it means **any** two render outputs can differ for reasons unrelated to the change
under test. Options: raise the limit, make the timeout a rendered fact (`/* decompilation timed out
*/`) rather than a silent skeleton fallback, or both. The second matters more than the first — a
reader cannot currently tell an empty function from one Ghidra gave up on.

---

## 39. The render is a source tree — DONE

Output files were named by replacing every non-identifier character of the source path with `_`, so a
header arrived as `E__work_cc_devtools_devtools-bluelab-7-0_result_include_imageutil_appimage.h`.
`renderAll` now writes `E/work/cc/.../imageutil/appimage.h`: drive letter as the top directory, both
separators honored, `..` popping the segment before it.

Three things fell out of it, in the order they were found.

**§15's fold was written for flat names and threw away the tree.** It folded every spelling onto the
*bare* one — `image.h` at the top level next to `main.cpp` — while the stabs knew the header lived in
`result/include/xvimage/`. It now folds onto a path, the shallowest when several agree on the parent
directory, since the least deeply nested spelling is the least specific to one build root: `image.h`
under the Jenkins root while its siblings sat under the devtools root split one include tree in two.

**`BlockScope.source` was never folded**, and `inlineParams` compares it against the file being
rendered. It matched only while the fold picked the bare spelling that `N_SOL` usually uses; folding
onto the full path exposed it and every pseudo-call in xvimage.cpp lost its parameter names to the
dataflow fallback (`__inline_xvimage_h_27(startAddr)` for `(aStart, aStart)`). Folding blocks with
everything else fixed it — and recovered two inline-stretch definitions in unpackfile's
filesystemimage.h that had never rendered, which is where that fixture's 551 → 553 clang errors come
from (both in the "statements at file scope in a header view" family, above).

**Relative spellings are resolved against their CU's compilation directory.** gcc gave
`bits64.h` as `../../../interface/host/bits/bits64.h`, which landed under an invented `interface/`
root; anchored to the CU's `N_SO` directory it is
`C/Jenkins/.../bc/bluesuite_2_6/interface/host/bits/bits64.h`. Only spellings that *say* they are
relative are resolved — gcc writes bare filenames relative to the CU too, but resolving those gives a
staged header two different parent directories and stops the fold merging them, splitting `image.h`
into `devHost/util/image/image.h` and `result/include/xvimage/image.h`.

Two things the tree exposed that had been invisible: `safeName` kept `.`, so a `../`-relative path
became a *dotfile* (`.._.._.._interface_host_bits_bits64.h`) that `ls` and `tools/check-grammar.sh`
both skipped — the script globbed `$dir/*` and was silently scoring 9 of appquery's 66 files after
the move. It walks the tree now.

A header renders where the binary's CUs happen to name it: appquery has no full spelling of
`filesystemimage.h` at all (19 bare `N_SOL`s, no `-I` path), so it stays at the top level there while
unpackfile files it under `result/include/imageutil/`.

---

## 38. gcc drops the file of every deferred file-scope static — partly done

`main.cpp` renders **1456 rows for a file whose code ends at L166**. The other 1290 are twenty
`vmN_trapset_names` tables claiming L12, 82, 152, … 1342 — a 70-line stride, 65 names plus decl,
`};` and a blank each. They are not main.cpp's: `main` occupies L31–166, which the tables at 82 and
152 would have to interleave with. Their real home is
`imageutil/vmtrapsetnames.h`, and the render has no way to know it.

**Mechanism, confirmed in gcc's source.** `dbxout_prepare_symbol` emits an `N_SOL` for a symbol's own
`DECL_SOURCE_FILE` only under `#ifdef WINNING_GDB`, which no shipped build defines. So a file-scope
static's stab carries its declaration *line* in the desc and inherits whatever `N_SOL` was last in
effect for its *file* — and these are emitted in one batch after the last function, when the last
`N_SOL` is the CU. Nor is there an ordering to exploit: the batch is grouped by section and sorted by
address within it (`__ioinit` (.bss) before the tables (.rodata)), while `<iostream>`'s `BINCL` is
#480 against vmtrapsetnames.h's #316 — batch order is not include order. And vmtrapsetnames.h's
`BINCL` block is *empty* (checksum 0, an `EINCL` on the next record): the header declares no types, so
there is nothing bracketed to anchor it either.

**`activityExtent` could not flag them, for two reasons — DONE.** It took
`max(lines, symbols.declLine, spans.end)`, and `symbols.declLine` was read from the very symbols it
was meant to judge — extent 1342, so nothing was stale. That is the circularity priority-2 records
for typedefs in headers, reappearing on a `.cpp` through the symbol term; a file that defines
functions is now measured by its code alone (`lines`, `spans`), and one that defines none still has
only its declarations to go on. The second reason was quieter: **`emitGlobal` never set `stale` at
all**, so no global was ever judged, and fixing the extent by itself changed nothing. Both together
take main.cpp from **1456 rows to 251** and touch no other file in either fixture; seventeen tables
go to the appendix, and the three at L12/82/152 stay because they fall inside the code extent — which
is what the run-grouping above is for. Clang totals do not move (the tables were valid C++ wherever
they sat).

Two things the fix deliberately did *not* do:

- **Nothing tries to name the file.** See the grades below.

**The canvas follows, and it is where the skeleton gets its win.** `maxLine` now counts only
declarations that are not stale. Shrinking it *while the claim passes still gated on it* was the
trap: a declaration off the end of a shortened canvas is then never **built**, so it never reaches
the stale partition either, and unpackfile.cpp's appendix silently lost 57 of its 78 entries. The
passes therefore no longer mention `maxLine` at all — they build every declaration, the allocator
turns a too-late one away as `OFF_CANVAS`, and `write` carries it to the appendix on the same path as
every other dropped claim. Appendix totals hold exactly (appquery 200, unpackfile 162, main.cpp's own
44) while the canvases collapse:

| skeleton            | before | after |
| ------------------- | ------ | ----- |
| main.cpp            | 1467   | 223   |
| filesystemimage.cpp | 928    | 203   |
| stl_uninitialized.h | 760    | 223   |
| vminfo.cpp          | 739    | 95    |
| image.cpp           | 513    | 146   |

Decomp was already trimming its trailing blanks, so it moves only where a shorter canvas crams a
body's tail (`;` counts unchanged per file, clang totals still 735/551). Note this is *not* §33: the
blank space removed here was never between content, it was the run below the last real row.

**What is recoverable, in three grades.**

- **Exactly: the typeinfo objects — DONE.** `_ZTI5Image` desc 29, and `class Image` is at image.h
  **L29**; `_ZTI7XVImage` 36 = xvimage.h L36; `_ZTI8AppImage` 19 = appimage.h L19; `_ZTI8XDVImage` 18;
  `_ZTI15FileSystemImage` 28. The line is the *class's* declaration line, and the proof is that it is
  the same in every CU that emits the symbol — where the sibling `_ZTS` string gives one class five
  different lines across five CUs, so only `_ZTI` is re-filed. `staticsBySource` now demangles it back
  to its class (`Itanium.typeinfoClassOf`, the `AddressTableHandler` path the vtable lookup already
  used) and files it where that class *renders*. Five of appquery's seven land in the header that
  declares the class; the two `std::` ones fall back to the CU because their class is itself misfiled
  there, so they were already where the lookup would have sent them.

  Two things this needed that were not obvious. **`classSourceByName` is the wrong map** — it answers
  "which file does the type id belong to" and says main.cpp for `Image`, the first CU that defined it,
  while the render draws `class Image` in image.h; `effectiveSourceFor` is the render's own
  attribution and is what a symbol has to agree with. **And a typeinfo must not outrank its class**:
  filed at L29 it is a peer of the class body claiming the same row, and it crushed `class Image`'s
  twenty members onto one line. Hence `Owner.GENERATED`, ranked under every real declaration and in a
  group of its own so it cannot share either — compiler-generated data has no source line of its own,
  and the whole `_ZTI`/`_ZTS`/`_ZTV` family is now ranked that way. The typeinfo lands in its class's
  file, in the appendix, reading `L 29 (line already taken)` — right file, right line, and not on top
  of the declaration it was generated from.

  Net: `_ZTI5Image` went from five copies in five CUs to one, appendix totals 200 → 198 (appquery) and
  162 → 158 (unpackfile), no identifier lost from either render, clang totals unchanged.
- **Ruling the CU out at all: only a conflict does it, and only 2 of the 20 have one.** `vm2` at L82
  and `vm3` at L152 fall strictly inside `main`'s attested span (L49–167), and a file-scope definition
  cannot sit between a function's braces — while the N_SLINE attribution that puts `main`'s code on
  those lines is per-address and derived independently of the symbol stabs. That is the whole of the
  hard evidence. `vm1` at L12 sits above all code and is, on its own, indistinguishable from a genuine
  main.cpp table; the other 17 are merely past the code extent, which proves nothing, since a `.cpp`
  may declare globals after its last function.

  What carries the other 18 is **uniformity**: the lines are an exact arithmetic progression (stride
  70, no exceptions), the ordinals `vm1…vm20` ascend with them, and the addresses ascend through
  `.rodata`. One generated block cannot have three members in main.cpp and seventeen in a header with
  the progression unbroken across the boundary. So the rule worth implementing is *a hard conflict on
  any member of a uniform run condemns the run* — and outside such a run, a data-only static whose
  line collides with nothing cannot be shown to be foreign at all, and the CU stays its best available
  owner.

  An earlier draft of this section claimed the candidate home "must be a header whose `BINCL` block is
  empty". That excludes nothing: an empty block means a header contributed no *types*, which is not
  the same as contributing this data, and it says nothing whatever about the CU, which emits types and
  could still be the home. It is a weak prior for the guess below, not part of the argument.

  **DONE, as exactly that rule.** `FileRenderer.foreignRun` groups a file's file-scope statics by
  address into maximal runs whose declLines form an ascending arithmetic progression, keeps those of
  three or more, and condemns any run with a member inside an attested function span; the members go
  to the appendix reading `run crosses this file's code`. On appquery it fires once, on the twenty
  tables, and reaches the eighteen no per-symbol rule could — including `vm1` at L12, which sits above
  all of main.cpp's code and is otherwise indistinguishable from a real table of its own. The stride
  requirement is what keeps it from over-reaching: globals are emitted in declaration order, so plain
  "ascending" describes every file's global list, and one wrong span would then condemn all of it.
  unpackfile and xmltest are untouched, clang totals unchanged.

  Incidentally fixed: main.cpp's `#include` band. Includes are `BAND` claims filling the rows above
  the first anchored one, and the first was `vm1` at L12 — 11 rows for 17 includes, so six were
  dropped as `no free row in the band` and landed in the *displaced-declarations* appendix, which an
  include has no business in (it never had a line to lose). With the run condemned the band starts at
  L18 and all seventeen fit. The mislabelling is still there for any other file that crowds its top.
- **Only by inference: which of the 32.** Project-path headers over system ones cuts it to three
  here, and stem-matching `vm3_trapset_names` against `vmtrapsetnames.h` picks it out — but that is a
  guess and has to be rendered as one (`probably vmtrapsetnames.h L152`), never as attribution. The
  alternative is ground truth from outside the binary: the headers, or a supplied map.

---

---
## 33. Blank space dominates the render — DONE, compact by default

**Re-measured 2026-08-11**, after the attribution work collapsed image.h from 903 lines to 59 and its
siblings with it: unpackfile **15,614 of 18,194 rows blank (85%)**, 13,900 of that in 170 runs of 20+,
longest run still 973. appquery 19,470 of 22,581 (86%). So the project-header fix was worth ~1,000
rows and *the ratio did not move* — the expectation that misattribution was propping this number up
was wrong.

What it is instead is a handful of **stdlib headers we know almost nothing about**:

| file                | rows  | blank | content |
| ------------------- | ----- | ----- | ------- |
| `bits/locale_facets.h` | 1,601 | 1,581 | 20      |
| `limits`               | 1,846 | 1,424 | 422     |
| `bits/istream.tcc`     | 1,187 | 1,183 | **4**   |
| `bits/stl_vector.h`    | 1,091 |   929 | 162     |

Four files are a third of all the blank space. `istream.tcc` renders 1,187 rows to show four, because
something is declared near line 1,187 and the canvas is line-aligned. That is the decision this
section is about, and it is not a misattribution bug: libstdc++'s locale_facets.h really is 1,600
lines and we really do know one thing near the end of it.

**Decided: compact by default, `--line-aligned` on request.** A run of blank rows collapses to one;
every row keeps the `L n` its content was placed at, so which line a row came from survives even
though its *position* no longer encodes it. unpackfile goes **18,194 rows to 3,128** (85% blank to
17%), `istream.tcc` from 1,187 rows to 6. The non-blank content is byte-identical between the two
modes and clang reports the same 521 errors on each, so nothing about the render changed except how
much nothing is in it. `--line-aligned` restores the old output for diffing against real source.

Not chosen: collapsing a run to a `/* … 340 lines … */` marker (keeps the count, but every reader
pays for a fact almost nobody needs), and capping the canvas at the last content (fixes only trailing
runs — `istream.tcc`'s 1,183 — and leaves interior gaps).

The original measurement, for comparison: 16,659 of 19,184 rows (87%), 15,327 in 156 runs of 20+.
Split by where it sits:

| where                                | rows  |
| ------------------------------------ | ----- |
| above the first content in a file    | 4,636 |
| inside a function span               | 6,259 |
| in a header with no functions at all | 5,764 |

The in-span blanks are mostly *not* reclaimable: a region spreads one statement per row and stops, so
2 statements in a 5-row window leave 3 blank, and the rows below a statement belong to source lines
whose code Ghidra folded into a neighbour. Filling them means either placing a statement above the
line it came from (eliminated in §29 — it was a third to a half of all rows) or padding, which spaces
apart things that belong together. Leave those.

The other 10,400 are worth attacking, and they are a different problem: a header whose first known
content is at line 500 renders 499 blank rows to get there, and one with 1,000 source lines and 20
rows of content is 98% empty. Alignment is why they exist, but nobody reads 973 blank rows — the
longest single run measured. Options, none free: collapse a long run to one `/* … 340 lines … */`
marker (compact, and the count keeps alignment *recoverable* but not literal); or render an
alignment-preserving file only on request and default to a compact one. Wants deciding before
implementing.

---

## `4900866` is not behaviour-neutral on a.out fixtures

Its message says *"Behaviour-neutral — unpackfile moves only the two reglocal counters"*. That was
checked on one PE fixture. Bisected on `zlib_aout_gcc263` (regenerate at `49a3838` vs `4900866`):

|                          | `49a3838` (parent) | `4900866` |
| ------------------------ | ------------------ | --------- |
| `empty-scope`            | 140                | **24**    |
| `reglocal-renamed-scope` | 5                  | **19**    |

Mechanism: it replaced address-sorted bracket processing (`buildBlocks` sorted brackets, claimed
locals by `recordIndex`) with stream-order processing. In unlinked `.o` files many brackets carry the
same unrelocated address, so the two orders build different trees — identical on PE, divergent on
a.out. All three a.out fixtures moved (`tinyxml` 298→49, `zlib` 140→24, `hello` 2→0).

**Open:** which tree is *correct* isn't established — fewer empty scopes may be the fix or may be
scopes being dropped. Any future neutrality claim here needs an a.out fixture in the check.

**Audit 2026-08-25: the disputed side is now pinned by a baseline.** `zlib_aout_gcc263`'s
`empty-scope` is **24** and its `reglocal-renamed-scope` **19** — both exactly the `4900866` column
of the table above, and `tinyxml_aout_gcc295`'s `empty-scope` is **49**, exactly the 298→49 that
section records. All point snapshots, so this is the shipped behaviour and not a mode artefact. So the behaviour shipped, was baselined, and any future change back would now read as
a regression against a number nobody has established is right. That is the sharpest edge left in
this file: not that it is unresolved, but that it is unresolved *and* frozen.

---

## Misattributed declarations and duplicate locals — DONE

**Stale N_SOL now goes to an appendix, not to its line.** Surveyed first across three programs:
every misattributed row is foreign. Win32 typedefs from `windows.h` misfiled into `crt1.c` (579),
libgcc internals (`USItype`, `DWunion`) misfiled into `cygwin.asm` — a `.asm` file holding 1060 rows
of C locals — and libstdc++ into `unpackfile.cpp` (46). tinyxml's and cryptopp's own sources have
**none**; it concentrates in whichever TU gcc used as the dumping ground. Project types appear only
as arguments to std templates (`_List_iterator<FileSystemEntry,…>`), which belong to the header.

A claim's line is the one thing about it known to be wrong, so rendering it there spent the file's
real estate on a lie: `unpackfile.cpp` is ~180 lines of source and rendered 977 rows because gcc
filed libstdc++ down to L898 in it. It now ends at 101. `crt1.c` 4486 → 1665 rows.

**Stabs locals merge into the decompiled head instead of contending for rows.** They are one set seen
twice — Ghidra recovers what it can from the frame and names it from the applied symbols, stabs has
the rest with gcc's own types. `DecompLine.declares` carries the head's names (read from
`ClangVariableToken`, not the rendered text); `decompClaims` appends what stabs has and Ghidra
doesn't, and `localClaims` skips bodied functions entirely.

Displaced-by-contention entries: unpackfile 267 → 48, tinyxml 2566 → 403, cryptopp 2073 → 600. The
few genuine additions are locals Ghidra lost, e.g. `TiXmlAttribute::SetDoubleValue` gains
`TiXmlAttribute * this;` — its decompiled signature dropped the `this` parameter.

**Open:** `activityExtent` uses `spans.ranges.isEmpty()` as a proxy for "is a header", and it leaks —
`filesystemimage.h` has spans (inline methods) so it takes the `.cpp` path. Right answer there by
luck. The real signal is probably distance: `class XVImage` sits 4 lines past attested code,
`bit_vector` sits 540 past.

---

## Render output is not parseable C++

`tools/check-grammar.sh <dir>` parses a render with clang. **Everything clang reports counts**,
except one named family: errors that follow from the render not emitting a definition for something
it names (`use of undeclared identifier`, `unknown type name`, `explicit specialization of
undeclared template`, …). Those are inherent to a per-file view of one translation unit, and no
clang flag turns them off, so they are subtracted by name. Ghidra's pseudo-types (`undefined4`,
`code`, `byte`, …) are a fixed vocabulary and get declared in a prelude rather than filtered.

The first version of this script did the opposite — whitelisted brace/paren messages — and scored 39
errors on unpackfile while hiding ~1500. Several hidden ones were real, cheap render defects. Do not
reintroduce a whitelist.

| render     | files with errors | errors |
| ---------- | ----------------- | ------ |
| unpackfile | 32/54             | 626    |
| tinyxml    | 69/110            | 1443   |
| cryptopp   | 151/250           | 2752   |

Three groups, by cost to fix:

**1. Mechanical spelling — cheap, self-contained (unpackfile counts).** Each is one rendering rule.

- `invalid parameter name: 'this' is a keyword` (77) — signatures render Ghidra's this-parameter
  literally as `this`. Fixing the signature is only half: the *call sites* still pass it
  (`find_slt(this,…)`), so the two halves disagree. See §37(d).
- `constructor cannot have a return type` (14), `destructor cannot have a return type` (8),
  `destructor cannot have any parameters` (8) — `void XVImage::XVImage(XVImage *this)`. Ghidra gives
  every function a return type; ctors and dtors must not print one.
- `brackets are not allowed here` (22) — `char const[18] _ZTS7XVImage = …` needs the extent after
  the name, `char const _ZTS7XVImage[18]`.
- `invalid digit 8 in octal constant` (7) — addresses print as `0040fbc0`, which C reads as octal.
  Needs `0x`.

**2. Statements at file scope in header views (`expected unqualified-id` 175, `a type specifier is
required` 112, and most `expected …`).** A header renders the code inlined *from* it, but nothing
emits an enclosing function for that code, so the statements sit at file scope where no C++ construct
admits them. Design gap, not a bug: these views would need to wrap each region in the member function
it came from.

**3. Nesting order in .cpp views — 7 rows across unpackfile where nesting goes negative.** Two fixed
already (see below); what remains is an orphaned `} else {` at xvimage.cpp L297 whose `if (…) {` is
placed elsewhere, and a surplus `}` at L473. Braces balance by *count* while nesting wrongly, so
per-file `{` vs `}` counting — which every check before this one used — reports these renders clean.

**Fixed so far.** Body claims are no longer reordered by the allocator: `claimsFor` builds ELASTIC
claims, and the elastic tie-breaks (row count, then first-row text) were alphabetising the statements
inside a function, which is how xvimage.cpp's first constructor got its closing brace two rows before
its last two statements. Bodies now compare equal on those keys and `sortedWith` stability keeps the
decompiler's order. Separately, `dropInlined` folded an inlined stretch's brace delta onto the
*following* region's last row, carrying braces over that region's statements; it now folds onto the
preceding region, as its own comment always said. Together: unpackfile 50 → 39 on the old whitelist.

**Group 1 done.** Each was one rendering rule:

- Pointers whose target Ghidra left undefined printed as the bare address, `0040fbc0`, which C reads
  as octal and rejects once a digit is 8 or 9. Spelled from the `Address` now, not by pattern-matching
  the rendered text, which cannot tell an address from a decimal.
- `renderDecl` puts an array's extent after the declarator, as C requires: `char const _ZTS7XVImage[9]`.
  Used by globals, fields, static members and locals.
- `asMemberDefinition` drops the return type Ghidra puts on every function when the function is a
  constructor or destructor, and drops its explicit `this` parameter. Applied to qualified definitions
  (deriving the class from `X::y`) and to class-body declarations (told the owner, having no qualifier
  to read).

unpackfile 626 → 503, cryptopp 2752 → 2565. **tinyxml went 1443 → 1649** and that is worth
understanding rather than averaging away: the group-1 errors are gone from it too, but removing the
explicit `this` turned 50 `invalid parameter name` plus 68 ctor/dtor errors into 167 `invalid use of
'this' outside of a non-static member function`. Both spellings are wrong for the same reason — the
class is not declared in that view — so this is group 2 resurfacing, not a new defect. Keeping the
parameter and renaming it to `self` instead was measured and is worse everywhere: 570/1653/2751
against 503/1649/2565.

**Group 2 done — the wrapper.** A header's inlined code is now enclosed in the function it was
compiled from, so it reads as a body rather than as loose statements at file scope. `wrapAsDefinition`
opens the first stretch with the function's signature and closes the last, counting braces over the
whole group; that subsumes the old per-stretch `balance()`, which made each stretch self-contained but
left them all outside any function.

The wrapper is a *free* function, deliberately. The class is usually not declared in the view, so
`Class::method` would not resolve and an implicit `this` would have nothing to bind to — the explicit
parameter stays and is renamed, along with every use in the body, because `this` is a keyword. This is
the same rename that was worse when applied to the whole render: right here, where there is no member
function to be implicit about, wrong for a qualified definition, which has one. A destructor's `~` is
also rewritten, a free function's name being unable to carry one, and duplicate class-body
declarations from gcc's aliased ctor/dtor copies are deduped (they render identically once the return
type and `this` are gone, and a class body cannot declare a member twice).

| render     | before group 1 | after group 1 | after group 2 |
| ---------- | -------------- | ------------- | ------------- |
| unpackfile | 626            | 503           | **396**       |
| tinyxml    | 1443           | 1649          | **1456**      |
| cryptopp   | 2752           | 2565          | **2224**      |

Brace-specific diagnostics: unpackfile 10, tinyxml 20, cryptopp 126. Not zero — group 3 is untouched.

**After group 2, two corrections and a limit.**

*The wrapper must not span a function's whole contribution.* Two functions inlined from one header
interleave by line, so a wrapper over everything one function contributed nests as `A{ B{ A} B}`;
that took unpackfile from 7 rows of negative nesting to 14, worse than before group 2. It now wraps
**consecutive** stretches only, which cannot interleave. Clang's brace diagnostics on unpackfile:
10 group-spanning → **3**. Adjacent stretches share one head, so a
`vector<Exclusion,…>::operator=` signature stands over its five consecutive stretches instead of
being repeated above each — 644 heads down to 572, and 594 total errors down to 432.

*Template instantiations are specialisations.* `class fpos<int> { … };` is not legal C++;
`template<> class fpos<int> { … };` is, and gcc's stabs describe instantiations, never the primary
template. Correct spelling, but **zero measured effect** — those lines already carried other errors.

**The checker's total is inflated and is not a to-do list.** An undeclared template makes `<`
ambiguous, so clang cannot tell a template argument list from a less-than and reports a *syntax*
error for what is really a missing declaration. Minimal repro: the same specialisation draws 4 errors
with its templates undeclared and 1 with them declared. Since the render names far more templates
than it defines, an unknown but large share of `expected unqualified-id` / `expected expression` /
`expected ')'` is this artifact, and it scales with how many signatures are printed — which is why
per-stretch wrapping improves the braces while raising the total. Declaring `namespace std` in the
prelude was tried and changes nothing; the templates, not the namespace, are what clang needs.
**Judge render changes on the brace diagnostics and on negative-nesting rows, not on the total.**

| render     | total | brace diagnostics |
| ---------- | ----- | ----------------- |
| unpackfile | 432   | 3                 |
| tinyxml    | 1485  | 20                |
| cryptopp   | 2910  | 94                |

**Open.**

- ~~**Group 3, brace nesting.**~~ Done in §34: balance is not nesting, and the fix is the running
  depth's low-water mark plus monotonic body anchors.
- **Forward declarations for referenced templates** would make the total mean something again, but
  arity varies per instantiation (default arguments), so a per-file `template<class,…> class X;` is
  not straightforwardly derivable.
- Note the checker is a shell script over clang, not a test; wiring it into `integrationTest` needs
  clang on the build box.

---

## Class attribution: `class Image` lands in stl_vector.h, image.h gets 903 rows of libstdc++ — SUPERSEDED

**Superseded by priority 2, which reversed both halves.** `class Image`, `XVImage` and `VmInfo`
all stay in their own headers, and image.h is **56 → 28 rows / 903 → 59 lines**. Kept for the
evidence table below — the four-CU `declSourceFile` disagreement is still the clearest statement
of why that signal cannot be trusted — but nothing here is open. Read priority 2 for what was done.

Original note, as written:

A straight swap, both directions, from the same unreliable signal. `image.h` is ~50 lines of source
and renders 903 rows containing no project code at all — only `vector<unsigned short>`,
`__normal_iterator`, `_Alloc_traits` and friends — while `class Image` is declared in
`c__mingw_include_c___3.2.3_bits_stl_vector.h`.

**Evidence.** `Image` has four type records, one per CU, and every one names a *different* libstdc++
header as its `declSourceFile`:

| CU emitting the `:T` body | declSourceFile        |
| ------------------------- | --------------------- |
| unpackfile.cpp            | `bits/stl_list.h`     |
| filesystemimage.cpp       | `bits/stl_list.h`     |
| xvimage.cpp               | `bits/basic_string.h` |
| image.cpp                 | `bits/stl_algobase.h` |

That is N_SOL at the moment gcc emitted the body — wherever the type first happened to be needed —
and it carries no information about where the class is written.

**Why the header vote cannot rescue it.** `multiSourceHeaderHints` votes over header N_SLINE entries
inside each method's address range. `image.h` has **zero** line entries: `Image`'s methods are all
out-of-line in image.cpp, so nothing was ever inlined from its header and it can never appear in any
vote. `userVote` is therefore empty and the `stdVote` fallback wins with stl_vector.h (70 entries).
The fallback is guarded only by `defSources.size > 1`, which is true of any class defined across
several CUs — the guard was meant to catch stdlib-only types and does not.

Contrast `XVImage`, which has 2 line entries in xvimage.h (something *was* inlined from it) and is
attributed correctly. So the defect is specific to a class with no inlined code.

**Fixed.** A method resolves to a `Func`, and `Func.cu` names the CU that defines it; C++ convention
puts the class in that CU's sibling header. When `userVote` is empty and every method of a type
resolves to one CU, that CU's sibling header now wins over the stdlib majority. `Image` → `image.h`,
and every project class across the three programs is correctly placed (the only class left inside a
libstdc++ header is `std::ios_base::Init`, which belongs there).

The sibling must already be a source the stabs name — nothing is synthesised, and a stem matching two
genuinely different files is dropped rather than guessed between. Building that candidate set from
`lineEntries` + `declSourceFile` was not enough: `image.h` is in neither, and exists only as some
type's `id.source`. **That is a coupling worth remembering** — `image.h` is a known source largely
*because* the misattributed instantiations were filed there, so fixing the second defect below could
make this lookup go dark.

**Second, separable defect.** The instantiations landing *in* image.h come from `effectiveSource`
trusting `declSourceFile` for typedefs. And `activityExtent` cannot flag them: for a file with no
function spans it falls back to counting type declarations, which is the same circularity fixed for
`.cpp` files — the misattributed declarations define the extent that is supposed to judge them.

## 53. Mangled-name resolution is symbol-table-bound, and the corpus now measures what that costs — open (measurement)

Several subsystems locate a thing by constructing its Itanium-mangled name and asking the symbol
table. That is fine on a linked PE with symbols and degrades sharply without them, and the corpus
now contains stripped twins of three fixtures, so the cost is visible for the first time:

| counter                                                         | unstripped | its `_stripped` twin |
|-----------------------------------------------------------------|------------|----------------------|
| `vtable-failed-truly-missing` (crypto_mi_test_gcc421_fullstabs) | 10         | **121**              |
| `vtable-failed-truly-missing` (locale_test_customlibstdcxx)     | 9          | **122**              |
| `static-member-unresolved` (both of the above)                  | 378        | **498**              |
| `static-member-applied` (both of the above)                     | 120        | **absent**           |

**The static-member half is by design, documented, and exact** — `applyAllStaticMembers`' own doc
says "Symbol-table-bound: a stripped binary resolves none", because a static member has no stab
address and can only link to the emitted symbol. The arithmetic confirms it to the unit:
378 + 120 = 498, i.e. the strip loses precisely the 120 the unstripped build applied and nothing
else moves. Nothing to fix; it belongs here as the calibration for the row above it.

**The vtable half is not**, and §25 records why: `ztvCandidates` cannot spell STL substitution
shorthand or templates, so the symbol index is not a fallback but the *only* path for those classes.
That is the difference between a subsystem that degrades on a strip and one that only ever worked
because of the symbol table.

Worth knowing before reading any stripped fixture's numbers, and worth a check when adding a
resolve-by-mangled-name path: ask which of the two it is. The unstripped `static-member-unresolved`
level itself (378 here, 393–409 on the PE fixtures, against 120–149 applied — a 3:1 miss rate with
symbols present) is unexplained and may be nothing, since gcc drops COMDAT statics; it has never
been looked at.

## 52. The N_SO/N_SOL address partition cannot attribute declarations — measured, closed

*Renumbered 2026-08-25: this was committed as a second §39 (`e821935`), colliding with "The render
is a source tree". Neither of the two `§39` cross-references in this file pointed here, so nothing
else needed changing.*

Read from the `.stab` sections directly (`locale_test_customlibstdcxx`, `appquery`,
`crypto_mi_test_gcc345`) and from gcc's own emitter, after three attempts to make the
partition beat `votedHeaderHints` all regressed. Do not retry without new evidence.

**What the records say.** Every CU closes — 61 opens / 61 closes (locale), 8/8 (appquery),
91/90 (crypto). But `dbxout_init` values the opening `N_SO` at `Ltext0` and dbxcoff.h's
`DBX_OUTPUT_MAIN_SOURCE_FILE_END` values the closer at `Letext`, and **both are labels in the
object's plain `.text`**. MinGW's libstdc++ puts every function in its own COMDAT section, so
those objects contribute nothing to plain `.text` and both labels collapse: 59 of 61 locale CUs
declare a zero-length span (all at `0x401a10`), 11 of 91 in crypto. The functions are in the
image regardless — 2945 of them — just not where the `Ltext` labels can see them.

So CU spans are *exact where non-empty* and *silent exactly for COMDAT-compiled objects*.
Coverage: appquery 17% of `.text`, locale 5%.

**Correction: the N_SOL *value* is unreliable for declaration provenance, not for code
attribution.** `TextPartitionProbe` scores each run against the N_SLINE entries landing inside it —
run bounds come from boundary addresses, entry attribution from record order, so agreement is not
circular. Sorted by address and closed by the next boundary, the runs are right about 9 times in 10:
appquery 88% (3414 own / 465 foreign over 1923 N_SOL runs), xmltest 95%, locale_test 69%; N_SO runs
97–100%. The error mass is a handful of long runs whose boundary was planted during the post-body
symbol flush while the next boundary is far away, so the run swallows unrelated code
(`basic_ios.tcc` own=2 foreign=433, `iomanip` own=2 foreign=94) — locale_test's 69% is four such
runs. Zero-length runs (117 / 61 / 22 boundaries colliding on one address) are artifacts with
nothing to publish, and are dropped at construction. Both records hardcode `desc` to 0, so a
published run says "this range came from file F, line unknown".

So `publishTextRanges` is defensible, and the precision fix is to publish a run only where its own
line entries endorse it (≥1 entry naming its file, majority agreeing) — that drops the flush-planted
mega-runs, which are the whole error mass. Not implemented; the probe already scores it.

**N_SOL addresses do not carry declaration provenance.** `dbxout_source_file` plants a fresh `Ltext<n>` at the current
assembly position after `text_section()`, and it is called from `dbxout_prepare_symbol` — before
*symbols*, not only before code. 1049 of 1232 boundaries (locale) and 2148 of 2169 (appquery) are
emitted while a function is open, i.e. during the post-body symbol flush. The N_SOL *record* is
sound and already load-bearing (`lineSource` → N_SLINE/symbol attribution → the burst vote); only
its value is noise. No difference between `-gstabs` and `-gstabs+` (crypto: identical 57/91/90).

**A COMDAT flag that is reliable**, two independent derivations, zero contradictions across the
three fixtures:

- *span rule* — the CU's declared span is zero-length, or the function's address falls outside it
  ⇒ the body was not in its CU's ordinary text run ⇒ separately sectioned. Total coverage
  (`unknown: 0`), flags 50/215, 2592/2662, 7787/8901.
- *multi-CU claim* — one address claimed by several CUs ⇒ the linker folded copies ⇒ the
  definition was shared. 9 / 136 / 1868 addresses; `_ZSt3minIjERKT_S2_S2_` is claimed by 30 CUs.
  A strict subset of the span rule (2013 cases, 0 contradictions), computable from
  `harvest.functions` alone — `groupBy { it.addr }`, no address arithmetic.

The span rule means "separately sectioned", *not* "came from a header": it also covers ordinary
functions from `-ffunction-sections` objects. Only the multi-claim subset implies a shared
definition. Note the useful part of `cuRanges` is the *emptiness* the producer currently drops.

**Three formulations tried as a tier above the burst vote, all regressions on appquery** (A/B via
two worktrees, `skeleton` over 4 fixtures, one-variable diff):

1. partition source at each method's entry → `XVImage` to `appimage.h`, `AppImage` to `main.cpp`
   (the case the hint exists to fix), `type_info` to `locale_facets.tcc`, `domain_error` to
   `time_members.h`. Its one win — `bad_alloc` 29 copies → 1, `type_info` 24 → 1 on locale — came
   from the noisy fallback tier, not the COMDAT one.
2. COMDAT-gap membership → never fires (gaps are 53 bytes of alignment padding; 0 functions in
   one), byte-identical output to HEAD.
3. multi-CU claim + the merged body's own first line → `XVImage` to `filesystemimage.h` with one
   copy, `appimage.h` voting all copies.

`votedHeaderHints` is unchanged and remains the best answer for out-of-line classes, which is the
case every address-backed signal is silent about.

**Two bugs found and fixed on the way.** `boundaryAddress` passed the open function's start into
`stabAddress`, so any boundary below it was rewritten as function-relative — 178 records in
appquery, and the unexplained `stab-value-func-relative` 5780 → 5958 baseline drift. dbxcoff.h
makes only line numbers and block addresses function-relative. And an empty CU span reached
`AddressSet.add` as `start > end`, killing 3 of 4 fixtures under the CLI (`assert` in the old
`TextRange` never fired — the CLI runs without `-ea`).

**Fourth attempt, and the one that works: require the merged copies to agree.** Measured first, by
`ComdatProvenanceProbe` (parser + harvester only, no autoanalysis; `build/test-output/comdat/`):
agreement is a clean discriminator. Instantiations agree and name their real defining header —
appquery 7 of 9 merged symbols, xmltest 47 of 63, crypto 1351 of 1868, all naming headers.
Disagreement is dominated by implicit ctor/dtor clones, which have no source text of their own:
2 of 2 on appquery, 16 of 16 on xmltest, 453 of 517 on crypto. So agreement is asked of the copies;
disagreement abstains and leaves the burst vote alone, which is what keeps `XVImage` in `xvimage.h`.

Render effect (A/B vs HEAD's vote, two worktrees, one-variable diff): 2 files changed on appquery,
xmltest and locale_test, 4 on crypto. No class lost or displaced, and every change a correction —
each moves a class from the file its *definitions* live in to the file that *declares* it:

- `vector<std::string>`: stl_alloc.h → stl_vector.h (joining `vector<unsigned short>`)
- `ctype<char>`: ctype_noninline.h → locale_facets.h (xmltest and crypto both)
- `__moneypunct_cache<wchar_t,true>`: locale_facets.tcc → locale_facets.h, and
  `__numpunct_cache<wchar_t>` gains a home there

`XVImage` and `AppImage` are untouched: their only merged members are dtor clones, whose copies
disagree, so the tier abstains and the burst vote still answers.

## 54. Secondary (virtual-base) sub-vtables are never laid — open (confirmed 2026-08-25)

A `_ZTV` object is not one table. A class with virtual bases gets a *group*: the primary vtable,
then one secondary sub-vtable per virtual base, each with its own
`[vcall offsets…] offset_to_top rtti [function pointers]`. `layVtable` lays the primary and stops at
the end of its function array (`vtableSlotTargets` halts at the first non-code word — which is the
next sub-vtable's `offset_to_top`). Everything after that is untouched.

`__ZTVSi` (`std::istream`, unpackfile `0x43ea7c`), read out of the PE:

```
+0   0x00000008  vbase offset (to basic_ios)   ← laid
+4   0x00000000  offset_to_top                 ← laid
+8   &__ZTISi    rtti                          ← laid
+12  __ZNSiD1Ev  ← address point, "vftable" label, 2 slots
+16  __ZNSiD0Ev
────────── virtual-base sub-vtable, entirely unannotated ──────────
+20  0xfffffff8  vcall offset
+24  0xfffffff8  offset_to_top
+28  &__ZTISi    rtti
+32  __ZTv0_n12_NSiD1Ev
+36  __ZTv0_n12_NSiD0Ev
```

Half the record on `Si`, two thirds on `Sd` (`std::iostream`, three sub-vtables).

**What that costs, in order:**

- `+32` is the address point a `basic_ios` subobject's vfptr holds. It gets no `vftable` symbol, so
  an upcast `basic_ios*` in the decompiler points at a raw address — the exact failure `layVtable`
  exists to prevent, one sub-vtable over.
- The `_ZTv0_n12_` virtual-call thunks stay untyped bare pointers, so a virtual call through a
  virtual base resolves to nothing.
- The secondary's `offset_to_top` (negative — the distance back to the complete object) and its vcall
  offsets carry the adjustment a reader needs to follow the thunk, and are unlabelled data.

**Why the §25 sweep cannot reach them:** it iterates *symbols*, and a secondary sub-vtable has none —
it is interior to the `_ZTV` object. Finding them means walking the record instead: after the primary
array, the next word begins another `[vcall…] offset_to_top rtti [fns]` triple, repeating until the
next symbol-bearing address. That is a different traversal from the one `sweepUnclaimedVtables` does,
and it applies to harvested and swept classes alike.

Slot typing for a secondary is not the primary's list re-laid: the entries are `_ZTv0_n<N>_` /
`_ZThn<N>_` thunks, which are distinct symbols with their own names and their own (identical)
signatures. Treat them the way §25 types swept slots — off the target's linkage name.

The count of sub-vtables should equal the number of virtual bases, giving the same cross-check
`vtable-vbase-count-mismatch` now applies to the primary's prefix.
