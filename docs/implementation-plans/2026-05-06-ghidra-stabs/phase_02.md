# ghidra-stabs Phase 2: Parser & AST

**Goal:** Convert stab descriptor strings into a sealed-class AST that covers every grammar form Cygwin gcc 3.4.4 emits — Sun base grammar plus the GCC class, size-attribute, and complex-type extensions.

**Architecture:** Pure-Kotlin recursive-descent parser over a `String` cursor. One method per grammar production. Errors throw `StabsParseException` carrying the cursor position and a snippet of the source string. No Ghidra dependencies in this layer.

**Tech Stack:** Kotlin 2.3.21, JDK 21, JUnit 5.

**Scope:** Phase 2 of 6.

**Codebase verified:** 2026-05-07.

**Codebase verification findings:**
- ✓ Phase 1 lands `container/Stabs.kt` (StabRecord/StabType/StabReader). Parser consumes assembled `record.name` strings from there.
- ✓ `parse_image/stabs_stats.py` is the canonical golden-corpus extractor (533 lines). It defines per-record kind detectors (`::` / `!` / `~%` for classes, `@s<n>` for size attrs, `R<n>;<size>;0;` for complex types).
- ✓ `parse_image/xapasmcsr.types.h` (generated decompiler output) lists hundreds of struct/typedef forms as a sanity reference for the parser's struct rule.
- ✗ The 10 explicit issue-#2 bug strings are referenced in the design but not yet collected into a corpus file. We must extract them as a fixture.
- ✗ No conformance note exists at `docs/notes/stabs-grammar-conformance.md` — must create.

**External dependency findings:**
- 📖 **Sun stabs grammar:** the canonical reference is the GNU `stabs.html` document (formerly distributed with binutils, now hosted at <https://sourceware.org/binutils/docs/stabs/>). Sections we cite: §2 ("Symbol Types"), §4 ("Type Definitions"), §5 ("Symbol Descriptors").
- 📖 **GCC `dbxout`:** `gcc/dbxout.c` in any GCC source tree (e.g., gcc-3.4.4 sources at `~/git/bouse/firmware/csr-gcc-3.3.3-30-xap-patch/gcc/gcc/dbxout.c` if needed) — this is the emitter side. Functions `dbxout_type`, `dbxout_type_methods`, `dbxout_class_name_qualifiers`. The conformance note cites these by line range.
- 📖 **GDB stabs reader:** `gdb/stabsread.c` — function `read_type`, `read_struct_type`, `read_member_functions`, `read_cpp_abbrev`. This is the reference parser we mirror.
- 📖 **Binutils stabs:** `bfd/stabs.c` and `binutils/stabs.c` — handles the link-time merging side. Less directly relevant to us (we read the merged output) but cited for completeness.
- 📖 **Issue-#2 bug strings:** the design lists three of them inline — `_Bool:t(0,21)=@s8;-16`, `complex float:t(0,16)=R3;8;0;`, `long long int:t(0,6)=@s64;r(0,6);…`. The other 7 are not in the design body; they must be harvested from `parse_image/stabs_stats.py` output (run it against `xapasmcsr.exe`) or derived from prior-art notes. **The implementor must surface this to the user before writing the test corpus** (see Task 7).

---

## Acceptance Criteria Coverage

This phase implements and tests:

### ghidra-stabs.AC2: Parser correctness against Sun + GCC grammar

- **ghidra-stabs.AC2.1 Success:** Parser produces the expected AST for every descriptor form in the `xapasmcsr.exe` golden corpus exported by `parse_image/stabs_stats.py`.
- **ghidra-stabs.AC2.2 Success:** Parser handles `@s<n>;<inner>` size attributes (`@s8`, `@s16`, `@s64`) on integer types.
- **ghidra-stabs.AC2.3 Success:** Parser handles `R<n>;<size>;0;` complex-type descriptors (`R3`, `R4`, `R5`).
- **ghidra-stabs.AC2.4 Success:** Parser handles full C++ class grammar: inheritance (`!`), method-with-mangled-symbol blocks (`::(...)=#...;:_Z…;<accessibility><modifier><virt>`), virtual offset markers (`*<voff>;<vthistype>;`), `~%` vtable-pointer marker, static fields (`/`).
- **ghidra-stabs.AC2.5 Failure:** Each of the 10 explicit issue-#2 bug strings parses to an AST without throwing; previously-failing strings (`_Bool:t(0,21)=@s8;-16`, `complex float:t(0,16)=R3;8;0;`, `long long int:t(0,6)=@s64;r(0,6);…`, etc.) all succeed.
- **ghidra-stabs.AC2.7 Edge:** Recursive type definitions (struct containing a pointer to itself) parse without infinite recursion.

### ghidra-stabs.AC6: Error handling

- **ghidra-stabs.AC6.2 Failure:** A single malformed stab record never aborts the run; it produces a `[Stabs] parse-error` log entry with the raw descriptor and the cursor position, and the importer continues. (The parser side: throwing `StabsParseException` with cursor info. The importer-catches-and-continues half lands in Phase 4.)

---

## Implementation Tasks

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: AST sealed hierarchies + supporting types

**Files:**
- Create: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/parser/Ast.kt`

**Implementation:**

Pure Kotlin, no Ghidra imports. The shape mirrors the design. All types are immutable `data class`es or `data object`s.

```kotlin
package ghistabs.parser

/** Identifies a type within a CU: (file-number, type-number). */
data class TypeId(val cu: Int, val n: Int)

enum class Access { PRIVATE, PROTECTED, PUBLIC }
enum class VirtKind { NORMAL, STATIC, VIRTUAL }
enum class AggrKind { STRUCT, UNION, CLASS }

/** Type AST. Sealed; every grammar form has a constructor here. */
sealed interface TypeDecl {
    /** Forward reference to a type defined elsewhere by id. */
    data class Ref(val id: TypeId) : TypeDecl
    /** Sun range descriptor: `r<id>;<min>;<max>;` — encodes integer/char widths. */
    data class Range(val of: TypeId, val min: Long, val max: Long) : TypeDecl
    data class Pointer(val pointee: TypeDecl) : TypeDecl
    data class Reference(val referent: TypeDecl) : TypeDecl
    data class Const(val inner: TypeDecl) : TypeDecl
    data class Volatile(val inner: TypeDecl) : TypeDecl
    data class Array(val element: TypeDecl, val length: Long?, val indexType: TypeDecl?) : TypeDecl
    data class Enum(val members: List<Pair<String, Long>>) : TypeDecl
    data class Struct(
        val kind: AggrKind,
        val sizeBytes: Long,
        val bases: List<BaseDecl>,
        val fields: List<FieldDecl>,
        val methods: List<MethodDecl>,
        val hasVTablePointerMarker: Boolean,
        val vtableTargetTypeId: TypeId?,
    ) : TypeDecl
    data class FunctionT(val ret: TypeDecl, val params: List<TypeDecl>) : TypeDecl
    /** Pointer-to-member-function (the `#` descriptor body). */
    data class Method(val cls: TypeDecl, val ret: TypeDecl, val params: List<TypeDecl>) : TypeDecl
    /** GCC complex/floating: `R<n>;<size>;0;`. n encodes 3=cfloat, 4=cdouble, 5=cldouble per gcc/dbxout. */
    data class Complex(val rCode: Int, val sizeBytes: Int) : TypeDecl
    /** Cross-reference: `xs<name>:` / `xu<name>:` / `xc<name>:` — incomplete tag. */
    data class XRef(val kind: AggrKind, val tagName: String) : TypeDecl
    /** Wrapper carrying an `@s<n>;` size attribute around an inner type. */
    data class WithSizeAttr(val sizeBits: Int, val inner: TypeDecl) : TypeDecl
    /** Builtin form `(0,N)` resolved by id only — content provided by BuiltinTable in Phase 3. */
    data object Builtin : TypeDecl
}

data class FieldDecl(
    val name: String,
    val type: TypeDecl,
    val offsetBits: Long,
    val sizeBits: Long,
    val isStatic: Boolean,
)

data class BaseDecl(
    val type: TypeDecl,
    val isVirtual: Boolean,
    val access: Access,
    val offsetBits: Long,
)

data class MethodDecl(
    val name: String,
    val mangled: String?,
    val signature: TypeDecl.Method,
    val access: Access,
    val virt: VirtKind,
    val isConst: Boolean,
    val isVolatile: Boolean,
    /** Vtable offset in bits when `virt == VIRTUAL`, else null. */
    val vtableOffsetBits: Long?,
)

/** Symbol AST: what one stab record's `name:descriptor` decodes to. */
sealed interface SymbolDecl {
    val name: String
    /** `:F` / `:f`. Top-level function (file-static if `f`). */
    data class Function(override val name: String, val isFileStatic: Boolean, val signature: TypeDecl) : SymbolDecl
    /** `:p` */
    data class StackParam(override val name: String, val type: TypeDecl) : SymbolDecl
    /** `:P` (register param) or `:R` (alt). */
    data class RegParam(override val name: String, val type: TypeDecl, val regNum: Int) : SymbolDecl
    /** `:r` register variable. */
    data class RegLocal(override val name: String, val type: TypeDecl, val regNum: Int) : SymbolDecl
    /** Plain stack local (an `:` descriptor with no class letter, or `:V` static-local). */
    data class StackLocal(override val name: String, val type: TypeDecl) : SymbolDecl
    /** `:T` tagged type (struct/union/class/enum tag). */
    data class TaggedType(override val name: String, val id: TypeId, val body: TypeDecl) : SymbolDecl
    /** `:t` typedef. */
    data class Typedef(override val name: String, val id: TypeId, val body: TypeDecl) : SymbolDecl
    /** `:G` */
    data class Global(override val name: String, val type: TypeDecl) : SymbolDecl
    /** `:S` file-static / `:V` static-local. */
    data class StaticVar(override val name: String, val type: TypeDecl, val isFunctionLocal: Boolean) : SymbolDecl
}

class StabsParseException(
    val pos: Int,
    val src: String,
    msg: String,
) : RuntimeException("at $pos in '${src.take(120)}': $msg") {
    /** Returns a one-line excerpt with a `^` caret at `pos`. */
    fun excerpt(): String {
        val start = (pos - 30).coerceAtLeast(0)
        val end = (pos + 30).coerceAtMost(src.length)
        val window = src.substring(start, end)
        val caret = " ".repeat(pos - start) + "^"
        return "$window\n$caret"
    }
}
```

**Step: Commit**

```bash
git add src/main/kotlin/ghistabs/parser/Ast.kt
git commit -m "feat(parser): AST sealed hierarchies + StabsParseException"
```

**Verifies:** None (pure types, no behavior).
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: `Cursor` primitive

**Files:**
- Create: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/parser/Cursor.kt`

**Implementation:**

Stateless-position cursor over the input string. Single owner: each `Parser` instance creates one and reads sequentially. The cursor centralises low-level scanning so the parser's productions are concise.

```kotlin
package ghistabs.parser

internal class Cursor(val src: String) {
    var pos: Int = 0
        private set

    val eof: Boolean get() = pos >= src.length

    fun peek(): Char =
        if (eof) throw StabsParseException(pos, src, "unexpected end of input")
        else src[pos]

    fun peekOrNull(): Char? = if (eof) null else src[pos]

    fun advance(): Char {
        val c = peek()
        pos++
        return c
    }

    fun startsWith(prefix: String): Boolean = src.startsWith(prefix, pos)

    fun consume(c: Char) {
        if (eof || src[pos] != c) {
            throw StabsParseException(pos, src, "expected '$c' but got '${peekOrNull() ?: "<eof>"}'")
        }
        pos++
    }

    fun consumeIf(c: Char): Boolean {
        if (!eof && src[pos] == c) { pos++; return true }
        return false
    }

    fun expect(s: String) {
        if (!startsWith(s)) throw StabsParseException(pos, src, "expected '$s'")
        pos += s.length
    }

    /** Read a (possibly negative) decimal integer terminated by a non-digit. */
    fun parseInt(): Long {
        val start = pos
        if (!eof && (src[pos] == '-' || src[pos] == '+')) pos++
        val numStart = pos
        while (!eof && src[pos].isDigit()) pos++
        if (pos == numStart) throw StabsParseException(start, src, "expected integer")
        return src.substring(start, pos).toLong()
    }

    /**
     * Read a stabs range bound. GCC emits range bounds in either decimal
     * (`-2147483648`, `2147483647`) or octal (`0`, `0177777`,
     * `01777777777777777777777` for `unsigned long long`'s max). A leading
     * `0` followed by another digit indicates octal. Plain `0` is decimal zero.
     *
     * Octal `01777777777777777777777` (= 2^64-1 = -1L) overflows signed
     * decimal Long.toLong() but parses correctly via radix-8 with
     * `java.lang.Long.parseUnsignedLong`. We then re-interpret the unsigned
     * value as a signed `Long`.
     */
    fun parseRangeBound(): Long {
        val start = pos
        var sign = 1L
        if (!eof && (src[pos] == '-' || src[pos] == '+')) {
            if (src[pos] == '-') sign = -1L
            pos++
        }
        val numStart = pos
        while (!eof && src[pos].isDigit()) pos++
        if (pos == numStart) throw StabsParseException(start, src, "expected range bound")
        val raw = src.substring(numStart, pos)
        val isOctal = raw.length >= 2 && raw[0] == '0'
        val magnitude = if (isOctal) java.lang.Long.parseUnsignedLong(raw, 8)
                        else java.lang.Long.parseUnsignedLong(raw, 10)
        // Reinterpret unsigned magnitude with sign applied. For the gcc
        // unsigned-overflow form (0..0xFFFFFFFFFFFFFFFF) sign is always +1
        // and the result equals -1L when magnitude == 0xFFFFFFFFFFFFFFFF.
        return sign * magnitude
    }

    /** Read `(cu,n)` or bare `n`. */
    fun parseTypeId(): TypeId {
        if (consumeIf('(')) {
            val cu = parseInt().toInt()
            consume(',')
            val n = parseInt().toInt()
            consume(')')
            return TypeId(cu, n)
        }
        val n = parseInt().toInt()
        return TypeId(0, n)
    }

    /** Read up to (but not including) any of the terminator chars. Consumed terminator is left in place. */
    fun readUntilAny(terminators: CharArray): String {
        val start = pos
        while (!eof && src[pos] !in terminators) pos++
        return src.substring(start, pos)
    }

    fun snapshot(): Int = pos
    fun restore(saved: Int) { pos = saved }
}
```

**Step: Commit**

```bash
git add src/main/kotlin/ghistabs/parser/Cursor.kt
git commit -m "feat(parser): Cursor primitive (peek/consume/parseInt/parseTypeId)"
```

**Verifies:** None directly.
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->

<!-- START_TASK_3 -->
### Task 3: `Parser` recursive descent — symbol-level entry + type descriptor dispatch

**Files:**
- Create: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/parser/Parser.kt`

**Implementation:**

One class with one method per production. Public entry `parseSymbol(name: String): SymbolDecl` and `parseTypeBody(name: String): TypeDecl` (used internally and exposed for tests). All other methods are `private`.

Production map (Sun + GCC, Cygwin gcc 3.4.4 dialect):

| Form | Production |
|------|------------|
| `name:F<type>` | function (top-level) |
| `name:f<type>` | function (file-static) |
| `name:p<type>` | stack parameter |
| `name:P<type>` | register parameter |
| `name:r<type>;<reg>` | register local/var |
| `name:G<type>` | global |
| `name:S<type>` | file-static var |
| `name:V<type>` | static local var |
| `name:T(cu,n)=<body>` | tagged type (struct/union/enum/class) |
| `name:t(cu,n)=<body>` | typedef |
| `name:<type>` (no descriptor letter) | stack local |

Type-descriptor dispatch (one-character lookahead, after `(cu,n)=`):

| Char | Production |
|------|------------|
| `(` or digit / `-` | `Ref` (forward) or recursion if followed by `=` |
| `*` | `Pointer` then recurse |
| `&` | `Reference` then recurse |
| `k` | `Const` then recurse |
| `B` | `Volatile` then recurse |
| `a` | `Array` |
| `e` | `Enum` |
| `s` | `Struct` (AggrKind.STRUCT) |
| `u` | `Struct` (AggrKind.UNION) |
| `Y` | `Struct` (AggrKind.CLASS) — gcc-2 form |
| `f` | `FunctionT` |
| `#` | `Method` (pointer to member function) |
| `r` | `Range` |
| `R` | `Complex` (`R<n>;<size>;0;`) |
| `x` | `XRef` (`xs<name>:` / `xu<name>:` / `xc<name>:`) |
| `@` | `WithSizeAttr` (`@s<n>;<inner>`) |

Note: a numeric/`(...)` lead in the type slot can mean either a forward reference OR `(cu,n)=<body>` (the latter is a *definition*; we may encounter it inline because gcc emits subordinate type definitions inside other types). The parser must check for `=` after the type-id and recurse appropriately.

Production-level rules:
- `parseStruct`: reads `<size>` (decimal) then optional inheritance section starting with `!<count>,<base-list>;`, then optional `~%<vtable-target-id>;` marker, then field/method list terminated by `;;`.
  - Each field: `<name>:<type>,<offset>,<size>;` for normal; `<name>:/<access><type>:_Z…;` for static; `<name>::<method-block>;` for methods.
  - Inheritance entry: `<virt><access><offset>,<base-id>;` where virt is `0`/`1`, access is `0`/`1`/`2`.
  - Method block: per gdb's `read_member_functions`: `(<count>=#<cls>,<ret>;<params>;):_Z<mangled>;<access><modifier><virt>[*<voff>;<vthistype>;]`.
- `parseEnum`: list of `<name>:<value>,` until trailing `;`.
- `parseFunctionT`: `f<ret>` — note: stabs function descriptors don't always carry parameter types in the type itself; parameters come via subsequent `:p`/`:P` records. So `FunctionT.params` is empty when parsed at type level. Method-of-class descriptors (the `#` form) DO carry param types.
- `parseRange`: `r<id>;<min>;<max>;`. Reads each bound via `Cursor.parseRangeBound()` (handles octal `0177…` and unsigned-overflow forms). For `long long unsigned int` gcc emits `r(0,7);0;01777777777777777777777;` — both bounds parse via radix-8.
- `parseComplex`: after the leading `R`, consume `<n>;<size>;0;` — the trailing `;0;` is a constant marker for "no scale".
- `parseSizeAttr`: after `@s<n>;` consume the inner type recursively. The size in bits is `n` (e.g. `@s64` ⇒ 64 bits).
- `parseXRef`: after `x`, the next char is the aggregate-kind code (`s`/`u`/`c`/`Y`); then read until the terminating `:`.

**Recursion + cycle handling at parser level:** the parser does NOT need to break cycles — that's Phase 3's `TypeRegistry` job. The parser produces a tree; `Ref(id)` nodes are returned for forward references and resolved later. This is why the parser cannot infinite-recurse on `struct A { A* next; }` — the `*` opens a `Pointer`, then the body is just `Ref(thisStructsId)`, no recursion.

**Skeleton to fill in:**

```kotlin
package ghistabs.parser

class Parser(src: String) {
    private val c = Cursor(src)

    fun parseSymbol(): SymbolDecl {
        val name = c.readUntilAny(charArrayOf(':'))
        c.consume(':')
        val descriptor = c.peek()
        return when (descriptor) {
            'F' -> { c.advance(); SymbolDecl.Function(name, isFileStatic = false, signature = parseType()) }
            'f' -> { c.advance(); SymbolDecl.Function(name, isFileStatic = true, signature = parseType()) }
            'p' -> { c.advance(); SymbolDecl.StackParam(name, parseType()) }
            'P' -> { c.advance(); SymbolDecl.RegParam(name, parseType(), regNum = readTrailingReg()) }
            'r' -> { c.advance(); SymbolDecl.RegLocal(name, parseType(), regNum = readTrailingReg()) }
            'G' -> { c.advance(); SymbolDecl.Global(name, parseType()) }
            'S' -> { c.advance(); SymbolDecl.StaticVar(name, parseType(), isFunctionLocal = false) }
            'V' -> { c.advance(); SymbolDecl.StaticVar(name, parseType(), isFunctionLocal = true) }
            'T' -> parseTagged(name)
            't' -> parseTypedef(name)
            else -> SymbolDecl.StackLocal(name, parseType())   // no descriptor letter
        }
    }

    private fun parseTagged(name: String): SymbolDecl.TaggedType { /* ... id=, body */ }
    private fun parseTypedef(name: String): SymbolDecl.Typedef { /* ... id=, body */ }
    private fun parseType(): TypeDecl { /* dispatch on lookahead */ }
    private fun parseStruct(kind: AggrKind): TypeDecl.Struct { /* ... */ }
    private fun parseEnum(): TypeDecl.Enum { /* ... */ }
    private fun parseRange(): TypeDecl.Range { /* ... */ }
    private fun parseComplex(): TypeDecl.Complex { /* ... */ }
    private fun parseXRef(): TypeDecl.XRef { /* ... */ }
    private fun parseSizeAttr(): TypeDecl.WithSizeAttr { /* ... */ }
    // ... etc.
}
```

The implementor fills in each production from the skeleton above, citing `gdb/stabsread.c` line numbers where the corresponding `read_*` function lives. Citations go in KDoc comments above each production:

```kotlin
/**
 * Read a class/struct/union body.
 * Mirror of gdb/stabsread.c:read_struct_type (~ line 3300 in stabsread.c gcc-3.4.4 era).
 */
private fun parseStruct(kind: AggrKind): TypeDecl.Struct { /* ... */ }
```

**Step: Compile-only check**

```bash
./gradlew compileKotlin
```

Expected: compiles cleanly. Tests in Task 5 will exercise behavior.

**Step: Commit**

```bash
git add src/main/kotlin/ghistabs/parser/Parser.kt
git commit -m "feat(parser): recursive-descent parser (one method per production)"
```

**Verifies:** None directly — exercised by tests in Tasks 5–7.
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Conformance note — production → source citation map

**Files:**
- Create: `/home/riton/git/bouse/ghidra-stabs/docs/notes/stabs-grammar-conformance.md`

**Implementation:**

Two-column table: column 1 is the parser method (`parseStruct`, `parseRange`, `parseComplex`, …), column 2 is the upstream citation. Cite at least one of `stabs.html §`, `gdb/stabsread.c:read_*`, `gcc/dbxout.c:dbxout_*` for every production.

Example rows:

| Parser method | Upstream citation |
|---------------|-------------------|
| `parseSymbol` | stabs.html §2 "Symbol Types"; gdb/stabsread.c:`define_symbol` |
| `parseStruct` | stabs.html §4.7; gdb/stabsread.c:`read_struct_type`; gcc/dbxout.c:`dbxout_type` |
| `parseEnum` | stabs.html §4.4; gdb/stabsread.c:`read_enum_type` |
| `parseRange` | stabs.html §4.5; gdb/stabsread.c:`read_range_type` |
| `parseComplex` | gcc/dbxout.c — emitted by `dbxout_type` for `COMPLEX_TYPE`; descriptor `R<n>;<size>;0;` |
| `parseSizeAttr` | gcc/dbxout.c — emitted as `@s<n>;` prefix in `dbxout_type` for sized integer types |
| `parseXRef` | stabs.html §4.6 "Cross-References"; gdb/stabsread.c:`read_cross_ref` |
| `parseStruct` (methods) | gdb/stabsread.c:`read_member_functions`; gdb/stabsread.c:`read_cpp_abbrev` for vtable marker |

Add a note section "Cygwin gcc 3.4.4 deviations from Sun":
- No negative builtin type IDs emitted (Sun's `-1` … `-34` table) — this confirms our skip in v1.
- `(cu,n)` always parenthesised — bare `n` only appears as the second half of a parenthesised pair.
- Some struct method blocks omit the trailing virtual marker (`*<voff>;<vthistype>;`) for non-virtual methods — `MethodDecl.virt` defaults to `NORMAL` in that case.

**Step: Commit**

```bash
git add docs/notes/stabs-grammar-conformance.md
git commit -m "docs(parser): grammar conformance map (productions → upstream citations)"
```

**Verifies:** Documentation deliverable from design Phase 2.
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_B -->

<!-- START_SUBCOMPONENT_C (tasks 5-7) -->

<!-- START_TASK_5 -->
### Task 5: `ParserTest` — primitive forms (range, size-attr, complex, builtins)

**Files:**
- Create: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs/parser/ParserPrimitiveTest.kt`

**Tests must verify:**

- `ghidra-stabs.AC2.2`: `_Bool:t(0,21)=@s8;-16` → `Typedef("_Bool", id=(0,21), body=WithSizeAttr(8, Builtin or Ref(?)))`. The `-16` tail is gcc's negative-builtin shorthand for `_Bool` — our parser produces a `Ref(TypeId(0,-16))` which BuiltinTable in Phase 3 maps to BoolDataType. Test asserts the AST shape, not the eventual mapping.
- `ghidra-stabs.AC2.2`: `int:t(0,1)=r(0,1);-2147483648;2147483647;` → `Typedef("int", id=(0,1), body=Range(of=(0,1), min=-2147483648L, max=2147483647L))`.
- `ghidra-stabs.AC2.2`: `long long int:t(0,6)=@s64;r(0,6);0000000000000;01777777777777777777777;` → `Typedef("long long int", id=(0,6), body=WithSizeAttr(64, Range(of=(0,6), min=0L, max=-1L)))`. (Octal min/max parsed via `Cursor.parseRangeBound()`; max octal `01777777777777777777777` = 2^64−1 = `-1L` when reinterpreted as signed Long.)
- `ghidra-stabs.AC2.3`: `complex float:t(0,16)=R3;8;0;` → `Typedef("complex float", id=(0,16), body=Complex(rCode=3, sizeBytes=8))`.
- `ghidra-stabs.AC2.3`: `complex double:t(0,17)=R4;16;0;` → `Complex(rCode=4, sizeBytes=16)`.
- Pointer-to-int: `pi:t(0,30)=*(0,1)` → `Typedef("pi", id=(0,30), body=Pointer(Ref((0,1))))`.
- Const-pointer-to-int: `cpi:t(0,31)=k*(0,1)` → `Typedef("cpi", id=(0,31), body=Const(Pointer(Ref((0,1)))))`.

Each test is a one-line input string + an `assertEquals(expected, parsed)` against a hand-built AST.

**Step: Run, then commit**

```bash
./gradlew test --tests 'ghistabs.parser.ParserPrimitiveTest'
git add src/test/kotlin/ghistabs/parser/ParserPrimitiveTest.kt
git commit -m "test(parser): primitives (range, complex, size-attr, pointer)"
```

**Verifies:** `ghidra-stabs.AC2.2`, `ghidra-stabs.AC2.3`.
<!-- END_TASK_5 -->

<!-- START_TASK_6 -->
### Task 6: `ParserTest` — C++ class grammar (inheritance, methods, vtable, statics)

**Files:**
- Create: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs/parser/ParserClassTest.kt`

**Tests must verify (`ghidra-stabs.AC2.4`):**

- Plain struct: `Foo:T(0,5)=s8x:(0,1),0,32;y:(0,1),32,32;;` parses to `TaggedType("Foo", id=(0,5), body=Struct(STRUCT, sizeBytes=8, bases=[], fields=[FieldDecl("x", Ref((0,1)), 0, 32, false), FieldDecl("y", Ref((0,1)), 32, 32, false)], methods=[], hasVTablePointerMarker=false, vtableTargetTypeId=null))`.
- Single inheritance with virtual: `Bar:T(0,6)=s4!1,0011,(0,5);;` (one base, public, non-virtual, offset 0, base-type-id (0,5)) → `bases.size == 1`, `bases[0] = BaseDecl(Ref((0,5)), isVirtual=false, access=PUBLIC, offsetBits=0)`.
- Class with vtable-pointer marker: `Baz:T(0,7)=s8~%(0,8);…;;` → `Struct(...).hasVTablePointerMarker == true`, `vtableTargetTypeId == TypeId(0,8)`.
- Method with mangled symbol: `Qux:T(0,9)=s4doIt::(0,10)=#(0,9),(0,1);(0,2);;:_ZN3Qux4doItEi;2A.;;` should produce `methods.size == 1` with `methods[0] = MethodDecl("doIt", mangled="_ZN3Qux4doItEi", signature=Method(cls=Ref((0,9)), ret=Ref((0,1)), params=[Ref((0,2))]), access=PUBLIC, virt=NORMAL, isConst=false, isVolatile=false, vtableOffsetBits=null)`. (`2A.` decoding: `2`=public, `A`=normal, `.`=end. The implementor verifies the modifier alphabet against gdb's `read_member_functions`.)
- Virtual method: same as above but with trailing `*0;(0,9);` (vtable offset 0, this-type (0,9)) — `virt == VIRTUAL`, `vtableOffsetBits == 0`.
- Static field: `Quux:T(0,11)=s4count:/02(0,1):_ZN4Quux5countE;;;` (static int count) → `fields[0].isStatic == true`.

The implementor cross-checks every example against `gdb/stabsread.c:read_member_functions` to confirm the modifier-letter alphabet.

**Step: Run, then commit**

```bash
./gradlew test --tests 'ghistabs.parser.ParserClassTest'
git add src/test/kotlin/ghistabs/parser/ParserClassTest.kt
git commit -m "test(parser): C++ class grammar (inheritance, methods, vtable, statics)"
```

**Verifies:** `ghidra-stabs.AC2.4`.
<!-- END_TASK_6 -->

<!-- START_TASK_7 -->
### Task 7: `ParserTest` — issue-#2 bug strings, error reporting, recursive types, golden corpus

**Files:**
- Create: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs/parser/ParserBugfixTest.kt`
- Create: `/home/riton/git/bouse/ghidra-stabs/src/test/resources/corpus/issue2-strings.txt`
- Create: `/home/riton/git/bouse/ghidra-stabs/src/test/resources/corpus/xapasmcsr-stabs.txt` (one stab descriptor per line, harvested via `parse_image/stabs_stats.py`)

**Tests:**

- **`ghidra-stabs.AC2.5`** (issue-#2 strings):
  - Read each line of `issue2-strings.txt`.
  - For each line, `Parser(line).parseSymbol()` must succeed (no exception) AND return a non-null `SymbolDecl`.
  - The first three lines are exactly:
    ```
    _Bool:t(0,21)=@s8;-16
    complex float:t(0,16)=R3;8;0;
    long long int:t(0,6)=@s64;r(0,6);0000000000000;01777777777777777777777;
    ```
  - The other 7 lines must be obtained from the user. **Surface a question to the user before writing the test:** "I have 3 of the 10 issue-#2 bug strings from the design body. Where can I find the remaining 7? (`parse_image/stabs_stats.py` output? Prior-art notes? Manually harvest from xapasmcsr.exe?)" Until the user supplies them, write the test to read whatever is in the file and pass — the assertion is about parsing success, not exact count.

- **`ghidra-stabs.AC2.6`** (parse-error reporting):
  - Input `garbage:T(0,1)=@@@?` ⇒ `Parser(input).parseSymbol()` throws `StabsParseException` with `pos > 0` and a non-empty `excerpt()` containing a `^` caret.
  - Catch the exception in the test (`assertThrows`), assert `e.pos in 14..18` (somewhere inside the `@@@?`), assert `e.excerpt().contains("^")`.

- **`ghidra-stabs.AC2.7`** (recursive types):
  - Input `Node:T(0,1)=s8next:(0,2)=*(0,1),0,32;val:(0,3),32,32;;` (struct Node containing a pointer to itself: field `next` is type `(0,2)`, defined inline as `*(0,1)` which forward-references the enclosing Node).
  - `parseSymbol()` must NOT infinite-recurse and must complete in < 100 ms.
  - Resulting AST: the `next` field's type is `Pointer(Ref(TypeId(0,1)))` — note the `Ref` is NOT yet resolved to a real Node (that's Phase 3's job). The parser only produces the tree.

- **`ghidra-stabs.AC2.1`** (golden corpus):
  - Read every line of `xapasmcsr-stabs.txt` (one descriptor per line). For each, call `Parser(line).parseSymbol()` and assert it does not throw.
  - Assert at least 1000 lines were processed (sanity guard against an empty corpus file).
  - **Corpus generation procedure** (run once by implementor, not by CI):
    ```bash
    cd /home/riton/git/bouse/parse_image
    # In a Ghidra Python window with xapasmcsr.exe loaded:
    #   exec(open('stabs_stats.py').read())
    # The script prints the histogram. Add a flag to dump every assembled
    # descriptor name to stdout, redirect to corpus file:
    pyghidra stabs_stats.py --dump-descriptors > \
        /home/riton/git/bouse/ghidra-stabs/src/test/resources/corpus/xapasmcsr-stabs.txt
    ```
    If `stabs_stats.py` does not yet have a `--dump-descriptors` flag, the implementor adds one (single-line addition) and commits both repos. Surface this to the user when starting the task: "I'll need to extend stabs_stats.py with a --dump-descriptors flag to harvest the corpus. OK?"

  - The test uses `Assumptions.assumeTrue(corpusFile.exists())` so CI without the corpus skips rather than fails.

**Step: Run, commit**

```bash
./gradlew test --tests 'ghistabs.parser.ParserBugfixTest'
git add src/test/kotlin/ghistabs/parser/ParserBugfixTest.kt \
        src/test/resources/corpus/issue2-strings.txt \
        src/test/resources/corpus/xapasmcsr-stabs.txt
git commit -m "test(parser): issue-#2 strings, error reporting, recursion, golden corpus"
```

**Verifies:** `ghidra-stabs.AC2.1`, `ghidra-stabs.AC2.5`, `ghidra-stabs.AC2.7`, `ghidra-stabs.AC6.2` (parser-throws-with-cursor half).
<!-- END_TASK_7 -->

<!-- END_SUBCOMPONENT_C -->

---

## Phase Done When

- [ ] `parser/Ast.kt` exports the full sealed AST hierarchy plus `StabsParseException`.
- [ ] `parser/Cursor.kt` exports the cursor primitives.
- [ ] `parser/Parser.kt` has one method per production with KDoc citations.
- [ ] `docs/notes/stabs-grammar-conformance.md` exists.
- [ ] `ParserPrimitiveTest`, `ParserClassTest`, `ParserBugfixTest` all green.
- [ ] Golden corpus file `xapasmcsr-stabs.txt` checked in (or test skips cleanly if absent).
- [ ] No infinite recursion on the Node-self-pointer case (test < 100 ms).

## Open Questions for User

- **Where are the 7 remaining issue-#2 bug strings?** The design body lists 3 explicitly. We need the others before Task 7 can be definitive. (Implementor: ask before writing.)
- **OK to extend `parse_image/stabs_stats.py` with `--dump-descriptors`?** Required for golden-corpus generation in Task 7.
