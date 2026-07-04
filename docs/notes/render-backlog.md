# Source-skeleton / decompilation render backlog

Open rendering issues in `render/`, captured from output review. Fixtures
regenerate under `build/test-output/{skeletons,decomps}/<binary>/`.

## 1. Single-line functions get no decompiled body — DONE

An inline accessor whose machine code all maps to one source line (e.g.
`AppImage::header_length() const`, all N_SLINEs on L17) was classified as a
single-line `FuncRange` (`isSingleLine`), rendered as a self-closing decl, and
skipped entirely by `applyDecompilation`. Now `applyDecompilation` defaults a
missing close line to the start line, so the whole body crams onto the one decl
line via the existing overflow path. Aliased out-of-line copies (ctor `C1`/`C2`,
dtor `D0`/`D1`/`D2`) collapse onto one line; decompiling each would stack
duplicate bodies, so a single-line function is only bodied when it is the sole
range on its line — aliases keep the skeleton's side-by-side decls.

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

## 5. Sweep findings (all fixtures, `--exclude-dir='*.old'`)

Structurally sound: `T_<digits>` dangling type refs = 0; no unparseable garbage.

- **Fixed:** single-line delimiter tags used the raw mangled name while multi-line
  closes used the demangled name; `emitFunctionBraces` now demangles both.
- **Fixed (common case):** orphan `;` from decompiler line-wrapping — harness
  `setMaxWidth(10_000)` (see #2).
- **Open — [C] raw mangled tags (~212):** `TypeAst.demangledName` calls the
  deprecated `DemanglerUtil.demangle` and falls back to the raw mangled name on
  failure, which fires **inconsistently** — the same `_ZN5ImageC1Ev` demangles to
  `Image` in decomp mode but stays mangled in skeleton mode. Almost all are
  ctor/dtor variants (`C1/C2/D0/D1/D2`). Fix: robust textual demangle (or special-
  case the Itanium ctor/dtor clones) so tags are stable across modes.
- **Open — [E] orphan punctuation (~9 files, decomp):** the decompiler still wraps
  *extreme* `std::` template member-access chains
  (`IncludePaths._base__Vector_base<…>._M_start`) even at width 10 000, leaving a
  lone `.`/`;`. Subsumed by the token-based rendering rework (#2).
- **Open — stale N_SOL in decomp (~108):** diagnostic comments that belong to
  skeleton mode leak into decomp output; trim them in decomp mode.
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
named param. The stab `StackParam`/`StackLocal` carries the matching frame offset
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

## 4. `_ZTS*` typeinfo-name globals + function overlap (xdvimage.cpp L131–133)

Three coupled defects around the RTTI typeinfo-name strings gcc attributes to a
single source line inside `XDVImage::symbol_start`:

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
off), run in the materialise transaction after `materialiseAll`, and enabled in the
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

## 8. Stack/register local injection — status (working; caveats)

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

## 10. Post-diagnostics-refactor: audit every log() level (OPEN)

After the diagnose refactor (log() is the single entry; degradations are WARN via the
`degradation()` extension), sweep every `log(...)` / `degradation(...)` call and set the
level deliberately: **WARN/ERROR** for real degradations, ordered by gravity; **INFO**
for non-trivial-but-not-bad signals; **DEBUG** for minutiae. The record*→log collapse
(§ diagnose) parked all former silent counters at DEBUG; some deserve promotion. Stale
comment to fix while there: StabsImporter `applyAllSymbols` still says "BookmarkSink
auto-bumps the counter" — no longer true (the accumulator counts, BookmarkSink only emits).

## 11. More log() calls should carry a bookmark address (OPEN)

Many diagnostics name a specific function/symbol/class but don't pass `address`, so they
only hit the MessageLog, not Ghidra's BookmarkManager (navigable markers). Sweep the WARN/
ERROR (and notable INFO) sites and pass the relevant address where one is in scope — e.g.
vtable-symbol-scan-error/vtable-rdata-scan-error (class addr), method-calling-convention
(func entry), parse-error (record addr if resolvable). Done so far: vftable-label-failed,
apply-error, vtable already carry addresses.

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
`TypeResolver` computes it once (`sourceCanonicalization`, seeded from `lineEntries.keys`,
`symbolsByCu.keys`, `functionSource.values`, and each type's `effectiveSource()` — none depend on
canonicalization, so no cycle) and exposes `canonicalSource(raw)` plus canonical-keyed fan-in views
`lineEntriesByCanonicalSource` / `symbolsByCanonicalSource` (re-sorted by (line, addr)). `Renderer`
canonicalises `sources`, and every `RenderContext` source comparison routes through `canon(...)`:
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

## 16 missing placeholder enum/struct xrefs

the return type of AppImage::image_type is supposed to be vm_image_type, an enum which is (i think) not defined because
only referenced as an xref. there should probably still be a placeholder enum for it though, with the right name

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
InlineDef target of a `typedef`), plus `typedef …;` aliases. `byCanonicalKey` groups by
`(category, ghidraName)`, so these land in *distinct* groups → the DTM materialises several
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
- **`TypeRegistry` typedef-skip.** The typedef materialisation phase no longer registers a `/stabs`
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

- **Open: enum double-registration → `.conflict`.** Naming the enums exposes a materialiser bug the
  dump makes obvious: `b2BodyType` is **one** `byCanonicalKey` group (18 members, `distinct=1`, fully
  content-equivalent) yet materialises as **two** DataTypes at the identical `/src/body.h/b2BodyType`
  slot, so Ghidra suffixes one `.conflict` (the decomp shows `EnumDSPRev.conflict`). This is a
  double-registration in `TypeRegistry.materialiseAll` (one content-equivalent group must yield exactly
  one DataType), not a grouping problem. `RegistryDump.duplicateNamedTypes` lists every such collision.
  Next step is to make the enum materialisation path register once per canonical group.
