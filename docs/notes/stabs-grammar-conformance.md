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

**Deviation:** Sun's stabs allowed negative type ID ranges (e.g., `-1` to `-34` for builtins). Cygwin gcc 3.4.4 does not
emit these.

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

**Deviation:** Cygwin gcc 3.4.4 uses `x<kind>` with kind ∈ {s, u, c, Y} (Y for class is gcc-2 holdover). Modern GDB also
recognizes this; Sun stabs did not standardize cross-references.

**Implication:** The parser accepts all four kinds and maps them to `AggrKind`.

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

- **Cygwin GCC 3.4.4 Specifics:**
    - The parser targets gcc-3.4.4 as used in CSR/Qualcomm ADK 4.0.1 firmware builds (circa 2006–2008).
    - No modern C++11+ features in stabs output (no `rvalue references (&& )`, no `noexcept`, etc.).
    - The `typedef` and `tagged type` `:t` / `:T` records are the primary way types are exposed; the parser must
      correctly parse both the inline body and the optional separate record.
