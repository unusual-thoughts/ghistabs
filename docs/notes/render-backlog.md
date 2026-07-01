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

## 3. Stack-local decl attribution — offset hypothesis

Stack locals may be rendered at a line derived from the definition offset that is
actually frame/ESP-relative, not a source line — so `SymbolDecl.StackLocal`
declLines land on the wrong row (see the `undefined2 in_stack_0000000e;` style
entries). Verify how `declLine` is computed for `StackLocal`/`StackParam` vs the
frame offset, and whether the offset is being conflated with a line number.

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
