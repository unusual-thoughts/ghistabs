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

## 2. Compress declarations at the start of decompiled functions

Ghidra emits every local as its own line at the top of a function
(`ushort value;` / `ushort uVar1;` / `undefined2 in_stack_...;`). These eat
vertical room and push the body's source-line alignment off. Use the decompiler's
**clang token stream** (`ClangTokenGroup` from `DecompileResults.getCCodeMarkup()`)
rather than the flat C text to identify the leading declaration block and fold it
onto one line (or the signature line), so real statements line up with their
N_SLINE source lines. Ties into better token-driven line flow generally
(`cleanDecompLines` currently works on raw text).

Interim: the harness sets `DecompileOptions.setMaxWidth(10_000)` so the
decompiler doesn't wrap long template-typed declarations into orphan
continuation lines (a bare `;`). This whole area — width, leading-decl folding,
line flow — is superseded once rendering works from clang tokens instead of the
flat C text.

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
redirects every reference and drops the typedef, freeing the name. Gated behind
`OPT_SHORTEN_TYPEDEFS` (default off), run in the materialise transaction after
`materialiseAll`. Pinned by `materialize/TypedefShorteningTest.kt` (pure, outputs the
renames) and `integration/TypedefShorteningProbeIntegrationTest.kt` (real fixture DTM:
dumps every rename to `build/test-output/typedef-renames/<fixture>.txt`, applies them,
asserts the std::string fold+rename landed).

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
