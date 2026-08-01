# STABS Grammar Conformance Map

This document maps each parser method in `ghistabs.parse.Parser` to its upstream sources: Sun stabs grammar (
stabs.html), GDB reference implementation (gdb/stabsread.c), and GCC emission side (gcc/dbxout.c).

## Parser Method → Upstream Citation

| Parser Method          | Upstream Citation                                                                                                | Notes                                                                                              |
|------------------------|------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------|
| `parseSymbol`          | **stabs.html** §2 "Symbol Types"; **gdb/stabsread.c** `define_symbol` (line ~700 in gcc-3.4.4 era)               | Dispatches on descriptor letter (F/f/p/P/r/G/S/V/T/t) or defaults to stack local.                  |
| `parseTagged`          | **stabs.html** §2; **gdb/stabsread.c** `define_symbol` (T case, line ~750)                                       | Tagged type: `:T(cu,n)=<body>`. Struct/union/enum/class tag definition.                            |
| `parseTypedef`         | **stabs.html** §2; **gdb/stabsread.c** `define_symbol` (t case, line ~760)                                       | Typedef: `:t(cu,n)=<body>`. Creates a type alias.                                                  |
| `parseType`            | **stabs.html** §4 "Type Definitions"; **gdb/stabsread.c** `read_type` (line ~2000)                               | Recursive dispatch on lookahead character. Core of the grammar.                                    |
| `parseStruct`          | **stabs.html** §4.7 "Structures"; **gdb/stabsread.c** `read_struct_type` (line ~3300)                            | Reads aggregate (struct/union/class) body with fields, methods, inheritance, vtable markers.       |
| `parseInheritanceList` | **gdb/stabsread.c** `read_cpp_abbrev` (line ~3500); **stabs.html** §4.7 "Class Inheritance"                      | Parses C++ inheritance list after `!`. Format: `!<count>,<virt><access><offset>,<base-id>;…`       |
| `parseMethodBlock`     | **gdb/stabsread.c** `read_member_functions` (line ~3600); **gdb/stabsread.c** `read_cpp_abbrev` (line ~3500)     | Method definition in struct: `(<count>=#<cls>,<ret>;<params>;):_Z…;<access><modifier><virt>`       |
| `parseEnum`            | **stabs.html** §4.4 "Enumerations"; **gdb/stabsread.c** `read_enum_type` (line ~2900)                            | Enumeration body: `e<name>:<value>,<name>:<value>,…;`                                              |
| `parseRange`           | **stabs.html** §4.5 "Ranges"; **gdb/stabsread.c** `read_range_type` (line ~2950)                                 | Integer/char range: `r<id>;<min>;<max>;`. Bounds parse via `Cursor.parseRangeBound()`.             |
| `parseComplex`         | **gcc/dbxout.c** `dbxout_type` (COMPLEX_TYPE case); **gcc/dbxout.c** `dbxout.c:1200` (gcc-3.4.4)                 | GCC complex/floating: `R<n>;<size>;0;` where n=3 (cfloat), 4 (cdouble), 5 (cldouble).              |
| `parseSizeAttr`        | **gcc/dbxout.c** `dbxout_type` (size-attribute emission, line ~1150); **gcc/dbxout.c** "Type attributes" section | GCC extension: `@s<bits>;<inner>`. Size attribute wrapper for sized integer types.                 |
| `parseXRef`            | **stabs.html** §4.6 "Cross-References"; **gdb/stabsread.c** `read_cross_ref` (line ~3000)                        | Incomplete forward reference: `x<kind><name>:` where kind ∈ {s, u, c, Y}.                          |
| `parseArray`           | **stabs.html** §4.3 "Arrays"; **gdb/stabsread.c** `read_array_type` (line ~2800)                                 | Array type: `a<index-type>;<element-type>` with optional range bounds.                             |
| `parseFunctionT`       | **stabs.html** §4.8 "Functions"; **gdb/stabsread.c** `read_type` (f case, line ~2100)                            | Function type: `f<return-type>`. Params typically come via separate `:p`/`:P` records.             |
| `parseMethod`          | **gdb/stabsread.c** `read_type` (# case, line ~2120); **gdb/stabsread.c** `read_member_functions` (line ~3600)   | Pointer-to-member-function (PMF): `#<cls>,<ret>;<params>;`. Params inline (unlike standalone `f`). |

## Type Descriptor Characters (Dispatch in `parseType`)

| Character       | Production           | Upstream                                                             |
|-----------------|----------------------|----------------------------------------------------------------------|
| `*`             | `Pointer`            | **stabs.html** §4.2 "Pointers"                                       |
| `&`             | `Reference`          | **stabs.html** §4.2; GCC extension                                   |
| `k`             | `Const`              | **stabs.html** §4.2 "Qualifiers"                                     |
| `B`             | `Volatile`           | **stabs.html** §4.2 "Qualifiers"                                     |
| `a`             | `Array`              | **stabs.html** §4.3                                                  |
| `e`             | `Enum`               | **stabs.html** §4.4                                                  |
| `s`             | `Struct`             | **stabs.html** §4.7                                                  |
| `u`             | `Union`              | **stabs.html** §4.7                                                  |
| `Y`             | `Class` (gcc-2)      | **stabs.html** §4.7; GCC-2 form of class descriptor                  |
| `f`             | `FunctionT`          | **stabs.html** §4.8                                                  |
| `#`             | `Method` (PMF)       | GCC extension; **gdb/stabsread.c** line ~2120                        |
| `r`             | `Range`              | **stabs.html** §4.5                                                  |
| `R`             | `Complex`            | **gcc/dbxout.c** COMPLEX_TYPE handling                               |
| `x`             | `XRef`               | **stabs.html** §4.6                                                  |
| `@`             | `WithSizeAttr`       | **gcc/dbxout.c** size-attribute emission                             |
| `(`, digit, `-` | `Ref` or inline defn | **stabs.html** §4.1 "Type References"; allows `(cu,n)=<body>` inline |

## Cygwin GCC 3.4.4 Deviations from Sun

This section documents where Cygwin gcc 3.4.4 (circa 2005) diverges from the original Sun stabs specification or
baseline GDB reader.

### 1. No Negative Builtin Type IDs

**Deviation:** Negative type ID ranges (`-1` to `-34` for builtins) are a **GNU/gdb** convention, not a Sun one — the Sun
spec (see References) never uses them, numbering every type with a `(file,type)` pair. Cygwin gcc 3.4.4 does not emit
them either.

**Implication:** The parser does not recognize or special-case negative IDs; all forward references use non-negative
`(cu, n)` pairs. The builtin type table (Phase 3) is consulted only for positive IDs like `(0, 21)` for `_Bool`.

### 2. Parenthesized Type IDs

**Deviation:** Cygwin gcc 3.4.4 consistently emits `(cu,n)` with parentheses. Bare type references (without parentheses)
appear only as the second element of a pair, never standalone in Cygwin output.

**Implication:** The `Cursor.parseTypeId()` method correctly handles both forms (for compatibility) but Cygwin sources
reliably use the parenthesized form.

### 3. Method Virtuality Markers

**Deviation:** Some struct method blocks omit the trailing `*<voff>;<vthistype>;` marker for non-virtual methods. The
`MethodDecl.virt` field defaults to `NORMAL` when the marker is absent.

**Implication:** The parser must handle both:

- Virtual: `(*<voff>;<vthistype>;)` present ⇒ `virt = VIRTUAL`, `vtableOffsetBits = voff`
- Non-virtual: marker absent ⇒ `virt = NORMAL`, `vtableOffsetBits = null`

### 4. Size Attributes on Integral Types

**Deviation:** Cygwin gcc 3.4.4 emits `@s<bits>;` size attributes on certain types (`_Bool`, `long long`) that need
explicit size representation beyond the range bounds. This is a GCC extension not in original Sun stabs.

**Implication:** The parser must correctly handle `WithSizeAttr` wrapping inner types (typically `Range`).

### 5. Complex Type Encoding

**Deviation:** The `R<n>;<size>;0;` format for complex floating types is a GCC extension. The trailing `;0;` is a
constant marker indicating "no scale factor."

**Implication:** The parser expects exactly this format; other schemes (if any) are not recognized.

### 6. Cross-Reference Kinds

**Deviation:** Sun *does* standardize the forward reference — `x [ e | s | u | Type ] name`, and its worked example emits
the same `xsS:` gcc does. The divergence is narrower than "gcc invented it": gcc adds the kinds `c` (class) and `Y`
(gcc-2 class holdover) to Sun's `e`/`s`/`u`, and Sun additionally allows a **type pair** in the kind position
(`x(0,5)name`), which gcc never emits and this parser does not accept.

**Implication:** The parser accepts the four gcc kinds and maps them to `AggrKind`. A Sun-produced binary using the
type-pair form would fail to parse — out of scope, but the reason is a real grammar gap, not an unsupported dialect.

## Sun-Only Constructs (verified absent from gcc's emitter)

Checked by diffing the Sun spec's descriptor inventory against `gcc/dbxout.c` emission sites. None of these can appear
in a binary this importer targets, so the parser's silence on them is correct, not a gap:

| Sun construct | What it is | gcc emission sites |
|---|---|---|
| `b`, `D`, `F`, `g`, `K`, `z` | basic integer, dope vector, function parameter, function-with-prototype, restricted, C99 VLA | **0** — gcc never emits any of them |
| `d`, `S` | Pascal `FILE_TYPE`; `SET_TYPE` (prefixed `@S;`) | 1 each, but only from the Pascal/Modula front ends — unreachable from C/C++ |
| `Y…` family (`Ya`, `Yn`, `YM`, `YD`, `YT`, `YI`, `YR`) | Sun's C++ encodings: anonymous unions, namespaces, pointer-to-member, templates, RTTI | gcc uses `Y` only as the gcc-2 class descriptor; the two-letter forms are Sun-only |
| `N_XLINE` (0x45) | line numbers > 65535: sets a state variable OR-ed into the high 16 bits of subsequent `N_SLINE`s | never emitted — gcc has no escape for the 16-bit `desc`, so line numbers past 65535 are simply unrepresentable |
| `N_USING` (0xc4) | C++ `using` declarations and directives | never emitted — a `using` leaves no trace in gcc stabs |
| `N_TCOMM`, `N_TFLSYM`, `N_TLCSYM`, `N_TSTSYM` | thread-local storage | never emitted |
| `N_SO_C`, `N_SO_CC`, `N_SO_FORTRAN`, … | source-language codes carried in `N_SO`'s `desc` | gcc leaves `desc` at 0 |

Two GNU constructs run the other way — `#` (pointer-to-member-function) and `@s<bits>` (size attribute) are emitted by
gcc and absent from the Sun spec, which has no type-attribute mechanism at all. The self-referential void idiom
(`(x,y)=(x,y)`) is likewise undocumented by Sun; it stays a gcc convention established by reverse engineering.

## Testing Against These Deviations

The test suite (`ParserPrimitiveTest`, `ParserClassTest`, `ParserBugfixTest` in Phase 2) validates:

1. **Octal range bounds:** `parseRangeBound()` correctly handles both decimal and octal (e.g., `01777777777777777777777`
   for `unsigned long long` max).
2. **Size attributes:** `_Bool:t(0,21)=@s8;-16` parses to `WithSizeAttr(8, Ref(TypeId(0, -16)))`.
3. **Method virtuality:** Both virtual and non-virtual method cases produce correct `MethodDecl.virt` and
   `vtableOffsetBits`.
4. **Parenthesized IDs:** Type references like `(0,1)` parse as `TypeId(cu=0, n=1)`.
5. **Complex types:** `R3;8;0;` and `R4;16;0;` parse with correct rCode and sizeBytes.
6. **Cross-references:** `xs…:`, `xu…:`, `xc…:`, `xY…:` all produce `XRef` with correct `AggrKind`.

## References

- **Sun *Stabs Interface* manual**, Sun Studio 10, June 2004 (170 pp):
  <https://www.filibeto.org/sun/lib/development/studio_10/stabs.pdf>
    - The authoritative Sun-side spec, and far more complete than stabs.html on the `N_*` inventory (60 types) and on
      Sun's own C++ encodings. The `§` numbers cited in the table above are **stabs.html's**, not this document's.

- **stabs.html** (GNU Binutils documentation): <https://sourceware.org/binutils/docs/stabs/>
    - Section 2: "Symbol Types" and descriptors
    - Section 4: "Type Definitions" (all subsections)
    - Section 5: "Symbol Descriptors"

- **GDB stabsread.c** (GDB source tree, any version 5.x–8.x):
    - `define_symbol()` - Symbol-level dispatch
    - `read_type()` - Type descriptor dispatch
    - `read_struct_type()` - Aggregate parsing
    - `read_member_functions()` - Method parsing
    - `read_cpp_abbrev()` - C++ extension abbreviations
    - `read_enum_type()` - Enumeration parsing
    - `read_range_type()` - Range parsing
    - `read_array_type()` - Array parsing
    - `read_cross_ref()` - Cross-reference parsing

- **GCC dbxout.c** (GCC source tree, 3.x–4.x era):
    - `dbxout_type()` - Type emission (search for "COMPLEX_TYPE", "@s" size attributes)
    - `dbxout_class_name_qualifiers()` - Class/method name handling

- **Cygwin GCC 3.4.x Specifics:**
    - No modern C++11+ features in stabs output (no `rvalue references (&& )`, no `noexcept`, etc.).
    - The `typedef` and `tagged type` `:t` / `:T` records are the primary way types are exposed; the parser must
      correctly parse both the inline body and the optional separate record.
