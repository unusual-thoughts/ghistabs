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

## 6. Class body attributed to a .cpp instead of its header (AppImage → main.cpp)

`class AppImage : public XVImage` renders in `main.cpp`, though its methods
(`header_length`, `image_type`) correctly land in `appimage.h`. gcc emitted
AppImage's full `:T` definition only in main.cpp's CU (where it's used), so
`TypeAst.effectiveSource()` falls back to `id.source.filename` = main.cpp.

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
