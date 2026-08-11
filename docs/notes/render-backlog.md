# Source-skeleton / decompilation render backlog

Open rendering issues in `render/`, captured from output review. Fixtures
regenerate under `build/test-output/{skeletons,decomps}/<binary>/`.

## Priorities

Ranked by what a reader of the output gets per unit of work, as of the grammar pass. Sections are
numbered in the order they were *found*, not worked; this is the order to work them.

**Four that a reader hits immediately.**

1. ~~**§37(a), aliased copies render two and three times.**~~ — DONE, see §37(a).
2. **image.h is 903 rows of libstdc++.** The class-attribution half is fixed; the other half is not.
   `effectiveSource` trusts `declSourceFile` for typedefs, and `activityExtent` cannot flag the
   result because for a file with no function spans it falls back to counting type declarations —
   the same circularity fixed for `.cpp` files. Note the coupling recorded below: `image.h` is a
   known source largely *because* these are filed there, so this and the sibling-header lookup have
   to move together. **§38 is the third instance and the worst**: `main.cpp` renders 1456 rows for a
   166-line file because twenty misfiled tables reach L1342, and the extent term that should catch
   them is computed from them. Take §38's exact half (the RTTI family) with this one.
3. **§33, blank space.** 87% of rows, 92% of that in runs of 20+. Options were written up and never
   chosen; it needs a decision more than it needs work.
4. **`redefinition of X`** (16 on unpackfile). Duplicate declarations that survived the class-body
   dedup. Cheap and self-contained.

**Then — structural correctness that the counters do not fully see.**

5. ~~**Brace nesting.**~~ — DONE, see §34.
6. ~~**§37(b)+(c), claims cross function boundaries.**~~ — DONE, see §37(b)/(c).
7. **§37(d), member calls still pass `this`.** `find_slt(this,…)` ×5 while the definition it calls has
   had the parameter stripped, so the two halves of the render contradict each other. Mechanical, and
   the same token knowledge `renameThis` already uses — the grammar section's `'this' is a keyword`
   family fixed only the definition side.
8. **8 markers still outside their block**, where the block and the marker reach the row as separate
   fragments. Needs placing at fragment assembly in `TargetLine.render()` rather than in
   `dropInlined`.
9. **`activityExtent`'s header proxy.** `spans.ranges.isEmpty()` stands in for "is a header" and
   leaks: `filesystemimage.h` has spans from inline methods. Right answer there by luck.

**Structural debt, worth taking before more of the above.**

10. ~~**§35, stop reconstructing what the token tree knows.**~~ — DONE. What is left there is one
    diagnostic and a note that the item's premise about `toLines` was wrong.

**Lower — measurement, then long-standing limitations.**

11. **Forward-declare referenced templates.** Would make the error total mean something again (an
    undeclared template manufactures syntax errors), but arity varies per instantiation because of
    default arguments, so the declaration is not straightforwardly derivable.
12. **§37(g), resolve the vtable-slot call.** `(**(code **)(*(int *)this + 8))(…)` is an offset into a
    vtable whose type the render declares in the same file, so it can be spelled as the method it
    calls. Small, and it reads as a real call rather than arithmetic.
13. **§37(f), the displaced/stale tail.** 19 rows on a ~150-line file, four claiming lines 302–348.
    The `stale N_SOL` ones are the activity extent already saying they do not belong; this is the
    "Misattributed declarations" work applied to the trailing block rather than to placement.
14. §23 multi-vtable ABI, §24 RTTI wiring, §25 unannotated `_ZTV`, §26 bitfields, §30 unnamed
    parameters, §21 leftovers, and the `4900866` a.out neutrality question. All pre-date this pass and
    none block a reader of the render.

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

## 13. Struct/non-pointer by-value return uses wrong calling convention — DONE

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
string, and everything downstream (`Harvest.lineEntries` keys, `symbolsByCu`,
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
`effectiveSourceFor(it) == source`, `symbolsByCu[source]`). `lineEntries`/`symbolsByCu` are
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

## 22. Single-arbiter attribution: canon at the data layer, §20 merge folded — DONE

Plan `zesty-tinkering-sparkle` (single-source-of-truth attribution, remove canon threading, robust
grouping). The §15/§20 work had left three overlapping attribution/canon paths and a `canon()` footgun
threaded through 8 render sites.

- **Phase 1 — canon once, at the data layer.** New `Harvester.canonicalizeRenderSources()` post-pass
  (after `nameAnonymousTypedefTargets`, gated by `canonicalizePaths`) folds `LineEntry.source` /
  `SymbolRecord.sourceFile` and re-keys `lineEntriesByFile`/`symbolsByCu` to canonical once; the fold map
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

## 23. C++ ABI: itanium model is flat single-vtable — open (limitation, not a bug on corpus)

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

## 24. Last-resort RTTI typeinfo wiring — open (RttiStructs present but unwired)

`itanium/Vtable.kt`'s `RttiStructs` builds the authoritative `__cxxabiv1` typeinfo structs
(`classTypeInfoStructure` / `siClassTypeInfoStructure` / `vmiClassTypeInfoStructure(n)` /
`baseClassTypeInfoStructure`) but nothing consumes them yet — the vtable `rtti` field points at
`Undefined4*`. They are the implementation of last resort for the gcc-internal typeinfo records
the stabs don't fully carry. Two levels, in priority order:

- **Level B — typeinfo global present, its pseudo *type* stubbed (the common case on our exes).**
  The stabs *do* emit the typeinfo globals — `_ZTI8CSegment`, `_ZTI4Inst`, `_ZTI8ExprInst`,
  `_ZTI10CLexStream`, … — each typed `struct __{class,si}_class_type_info_pseudo const`. But the
  gcc-internal pseudo struct types aren't in the stabs (libsupc++ built without them), so they land
  as unresolved XRefs (`type=/stabs/__si_class_type_info_pseudo`) and get stubbed opaque. Fix:
  substitute the matching `RttiStructs` impl for the stub, keyed by XRef name — hook the same
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

## 25. `_ZTV` symbols with no stabs class are never annotated — open

`buildAndApplyVtable` runs per `LocatedType`, i.e. only for classes we harvested a `T`-stab
body for. libsupc++ is linked without stabs, so its own polymorphic classes — `std::type_info`,
`__cxxabiv1::__{class,si_class,vmi_class}_type_info` — have a `_ZTV…` symbol and a real vtable in
`.data` but no group, and `resolveVtableAddress` is never called for them. On unpackfile,
`__ZTVN10__cxxabiv120__si_class_type_infoE` at `0043e954` is the canonical 2-word shape
(`offset_to_top=0`, `rtti=0043e34c`, address point `0043e95c`), yet the address point keeps
Ghidra's auto-generated `PTR_~__si_class_type_info_0043e95c` instead of a `vftable` symbol +
`<Class>_vftable` struct.

§24 covers the same classes at the *typeinfo record* level (`RttiStructs` → `DemanglerReplacer`);
this is the vtable level. Fix: after the per-group pass, sweep `Itanium.vtableClassOf`-matching
symbols with no group and `layVtable` them. Lossy — with no method list the slot types can only
come from the demangled signatures of the functions the slots point at, so decide whether to lay
header + address-point label only, or synthesise the vftable struct from the slot targets.

Neither `dcinstShiftSCompatibility` nor `cSymLexStreamVtableAddressPointSkipsVbaseOffset` covers
this: both assert on the output of `buildAndApplyVtable` for a stabs-bearing class and skip
outright on any fixture without it.

## 26. Bitfields are laid at their containing byte, not as bitfields — open

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

## 32. Layout rewrite — DRAFTED, not started

The `Fragment`/`TargetLine` model and the emit-then-reconcile pass structure are being replaced:
front-positioned `/* L n */` provenance, claim-and-resolve allocation, and no `// stray:` bucket.
Design in [`docs/design-plans/layout-rewrite.md`](../design-plans/layout-rewrite.md). §29's five fixes
were all symptoms of the two decisions that draft removes.

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

## 40. The render is not reproducible under load — open

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
  different lines across five CUs, so only `_ZTI` is re-filed. `symbolsBySource` now demangles it back
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
## 33. Blank space dominates the render — 87% of rows, and it is concentrated

Measured on `unpackfile.exe` decomp output: **16,659 of 19,184 rows are blank (87%)**, and
**92% of that is in 156 contiguous runs of 20 rows or more** (15,327 rows). Split by where it sits:

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

## Class attribution: `class Image` lands in stl_vector.h, image.h gets 903 rows of libstdc++

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
