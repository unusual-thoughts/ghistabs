package ghistabs.parse

import ghistabs.parse.TypeDecl.Struct.*

/** Parse outcome. [Ok.trailing] carries the unconsumed-tail message; reporting is the caller's job. */
sealed interface ParseResult<out T> {
    data class Ok<T>(val inner: T, val trailing: String? = null) : ParseResult<T>

    // ParseResult<Nothing>, not Error<T>: covariance then makes an Error usable as any ParseResult<U>,
    // so [map] needs no unchecked cast to re-tag the failure branch.
    data class Error(val ex: StabsParseException) : ParseResult<Nothing>

    fun <U> map(transform: (T) -> U): ParseResult<U> = when (this) {
        is Ok -> Ok(transform(inner), trailing)
        is Error -> this
    }
}

/**
 * Recursive-descent parser for stabs type and symbol descriptors.
 * Implements Sun + GCC stabs grammar as emitted by Cygwin gcc 3.4.4.
 *
 * Entry points:
 * - [parseSymbol]: Parse a `name:descriptor` symbol declaration.
 * - [parseTypeBody]: Parse a type descriptor (used internally and by tests).
 *
 * All other methods are private productions — one method per grammar rule.
 *
 * **Trailing Input:** This parser is lenient with trailing input after a complete symbol.
 * If the input string contains multiple stab records or trailing terminators, they are
 * silently ignored. This is intentional — the caller is responsible for processing
 * multiple records or filtering trailing input as needed.
 */
class Parser(src: String) {
    private companion object {
        // gcc builtin negative type number for `int` (see BuiltinTable): the implicit type of
        // a value-only `:c=` constant.
        const val BUILTIN_INT = -1

        // gcc's XCOFF builtin slot for bool, and the shape its `-gstabs+` spelling decodes to.
        const val BUILTIN_BOOL = -16
        const val BITS_PER_BYTE = 8L
        val BOOL_ENUM_MEMBERS = listOf("False" to 0L, "True" to 1L)

        // Symbol chars that may follow `operator` in a method name (arithmetic, logical,
        // comparison, shift). Brackets/parens/comma are excluded — they carry no `<>` and
        // need no protection from template-depth tracking.
        const val OPERATOR_SYMBOLS = "+-*/%^&|~!=<>"

        // Chars that may legitimately follow a fully-parsed struct body: field/base/symbol
        // terminator or an inline-def field separator.
        val BOUNDARY_CHARS = setOf(';', ',')
    }

    private val c = Cursor(src)

    /**
     * A fully-parsed record ends at a terminator run; anything else is an unimplemented section
     * silently dropped by the parser's leniency (the `~%` bug was one such tail, once struct-local).
     */
    private val trailingMessage get() =
        if (remaining.any { it != ';' && !it.isWhitespace() }) {
            "@'${c.src.take(80)}': +'${remaining.trim().take(40)}'"
        } else {
            null
        }

    /**
     * Parse a type descriptor body, exposed for testing.
     */
    fun parseTypeBody(): ParseResult<TypeDecl<LocalTypeId>> = try {
        // Argument order matters: parseType() must run before trailingMessage reads the cursor tail.
        ParseResult.Ok(c.parseType(), trailingMessage)
    } catch (e: StabsParseException) {
        ParseResult.Error(e)
    }

    /**
     * Parse a symbol declaration: `name:descriptor` where descriptor may be
     * a single letter (F/f/p/P/r/G/S/V/T/t) followed by type body, or no letter
     * (stack local).
     *
     * Mirror of gdb/stabsread.c:define_symbol.
     */
    fun parseSymbol(): ParseResult<SymbolDecl<LocalTypeId>> = try {
        ParseResult.Ok(c.parseSymbol(), trailingMessage)
    } catch (e: StabsParseException) {
        ParseResult.Error(e)
    }

    /** Unconsumed tail after [parseSymbol]/[parseTypeBody] — the caller checks for full consumption. */
    val remaining get() = c.remaining

    private fun Cursor.parseSymbol(): SymbolDecl<LocalTypeId> {
        // gcc emits anonymous aggregates/enums with a *blank* (whitespace) tag name, not an empty
        // one. Normalise blank → "" here so "anonymous" is uniformly `name.isNullOrEmpty()` for every
        // downstream consumer (ghidraName, the §20 content merge, nameAnonymousTypedefTargets) — a
        // stray " " otherwise reads as a distinct named type and silently blocks unification.
        val name = readSymbolName().ifBlank { "" }
        consume(':')
        return when (val descriptor = peekOrNull()) {
            'F' -> {
                advance()
                SymbolDecl.Function(name, FunctionScope.GLOBAL, type = parseType()).also { skipScopeSpecifier() }
            }

            'f' -> {
                advance()
                SymbolDecl.Function(name, FunctionScope.FILE, type = parseType()).also { skipScopeSpecifier() }
            }

            'p' -> {
                advance()
                SymbolDecl.Param(name, parseType(), VariableLocation.STACK)
            }

            'P', 'R' -> {
                advance()
                SymbolDecl.Param(name, parseType(), VariableLocation.REGISTER)
            }

            'r' -> {
                advance()
                SymbolDecl.Local(name, parseType(), VariableLocation.REGISTER)
            }

            'G' -> {
                advance()
                SymbolDecl.Static(name, parseType(), StaticScope.GLOBAL)
            }

            'S' -> {
                advance()
                SymbolDecl.Static(name, parseType(), StaticScope.FILE)
            }

            'V' -> {
                advance()
                SymbolDecl.Static(name, parseType(), StaticScope.FUNCTION)
            }

            'T' -> parseNamedType(name, TypeNameKind.TAG)

            't' -> parseNamedType(name, TypeNameKind.TYPEDEF)

            'c' -> parseConstant(name)

            // No symbol-descriptor letter: a stack local whose type follows immediately, always
            // a type-number ref or inline def (`(cu,n)`, a bare number, or a negative builtin).
            // Any other letter is a symbol descriptor we don't implement — surface it, don't
            // silently misread it as a type (e.g. `a`/`s`/`x`/`R` would parse as array/struct/…).
            else if (peekStartsTypeId()) -> SymbolDecl.Local(name, parseType(), VariableLocation.STACK)

            else -> throw StabsParseException(pos, src, "unhandled symbol descriptor '$descriptor'")
        }
    }

    /**
     * Optional nested-function scope specifier `,<proc>,<enclosing>` after a function's type
     * (stabs.texinfo §Nested Procedures). The proc name is redundant with the symbol name and the
     * enclosing link is already carried by the Itanium mangling, so — like gdb — we drop it. Consumed
     * (not left trailing) to keep the unparsed-trailing guard reserved for genuinely-unmodeled input.
     */
    private fun Cursor.skipScopeSpecifier() {
        if (consumeIf(',')) readUntilAny(charArrayOf(';'))
    }

    // ===== Symbol-level productions =====

    /**
     * Parse `:T(cu,n)=<body>` (tag) or `:t(cu,n)=<body>` (typedef), and the body-less
     * forward-declaration forms `:T(cu,n)` / `:t(cu,n)` that gcc emits when the name is bound here
     * but the body is defined by a later stab (the `t` case is common with cygwin gcc 13+ on
     * box2d-style C++23 code). Mirror of `gdb/stabsread.c:define_symbol` (T and t cases).
     */
    private fun Cursor.parseNamedType(name: String, kind: TypeNameKind): SymbolDecl.NamedType<LocalTypeId> {
        advance()
        // GCC emits Tt for combined tag+typedef (e.g. typedef struct foo {} foo).
        if (kind == TypeNameKind.TAG) consumeIf('t')
        val id = readTypeId()
        val body = if (consumeIf('=')) selfDefToVoid(id, parseType()) else TypeDecl.Ref(id)
        return SymbolDecl.NamedType(name, kind, id, body)
    }

    /**
     * Parse `:c=<form>` — an addressless compile-time constant. Unlike every other symbol
     * descriptor, `c` is not followed by type information but by `=` and a form letter:
     * `i`/`b`/`c` integral value, `e <type>,<value>` typed integral, `r` real / `s` string /
     * `S` set (non-integral, unseen from g++/x86 — payload consumed, value 0).
     * Mirror of gdb/stabsread.c:define_symbol (c case).
     */
    private fun Cursor.parseConstant(name: String): SymbolDecl.Constant<LocalTypeId> {
        consume('c')
        consume('=')
        return when (advance()) {
            'i', 'b', 'c' -> SymbolDecl.Constant(name, TypeDecl.Builtin(BUILTIN_INT), readInt())

            'e' -> {
                val type = parseType()
                consume(',')
                SymbolDecl.Constant(name, type, readInt())
            }

            else -> {
                readUntilAny(charArrayOf(';'))
                SymbolDecl.Constant(name, TypeDecl.Builtin(BUILTIN_INT), 0)
            }
        }
    }

    /**
     * gcc encodes void as a type explicitly defined as itself: `(x,y)=(x,y)`. Recognise that at the
     * definition (`=`) site so it becomes [TypeDecl.Void]; a bare `name:t(x,y)` (no `=`, handled by
     * the caller's else-branch) stays a [TypeDecl.Ref] forward reference — it is *not* void.
     */
    private fun selfDefToVoid(id: LocalTypeId, body: TypeDecl<LocalTypeId>): TypeDecl<LocalTypeId> =
        if (body is TypeDecl.Ref && body.id == id) TypeDecl.Void else body

    // ===== Type descriptor dispatch =====

    /**
     * Parse a type descriptor by lookahead character.
     * Dispatches to specific productions: Pointer (*), Reference (&), Const (k),
     * Volatile (B), Array (a), Enum (e), Struct (s/u/Y), FunctionT (f), Method (#),
     * Range (r), Complex (R), XRef (x), WithSizeAttr (@), or forward reference.
     *
     * Mirror of gdb/stabsread.c:read_type.
     */
    private fun Cursor.parseType(): TypeDecl<LocalTypeId> = when (val ch = peekOrNull()) {
        'a' -> parseArray()

        'e' -> parseEnum()

        'f' -> parseFunctionT()

        '#' -> parseMethod()

        'r' -> parseRange()

        'R' -> parseComplex()

        'x' -> parseXRef()

        '@' -> parseSizeAttr()

        '*' -> {
            advance()
            TypeDecl.Pointer(parseType())
        }

        '&' -> {
            advance()
            TypeDecl.Reference(parseType())
        }

        'k' -> {
            advance()
            TypeDecl.Const(parseType())
        }

        'B' -> {
            advance()
            TypeDecl.Volatile(parseType())
        }

        's' -> {
            advance()
            parseStruct(AggrKind.STRUCT)
        }

        'u' -> {
            advance()
            parseStruct(AggrKind.UNION)
        }

        'Y' -> {
            advance()
            parseStruct(AggrKind.CLASS)
        }

        else if (peekStartsTypeId()) -> {
            // Forward reference, inline definition, or builtin slot: (cu,n) /
            // bare n, possibly followed by =.
            val id = readTypeId()
            when {
                // Inline definition: parse the body recursively and wrap in InlineDef
                consumeIf('=') -> TypeDecl.InlineDef(id, selfDefToVoid(id, parseType()))

                // Negative type number = gcc XCOFF builtin slot. Per the
                // stabs spec: "the idea of negative type numbers is simply
                // to give a special type number which indicates the builtin
                // type. There is no stab defining these types." So bind
                // straight to [TypeDecl.Builtin] instead of leaving a
                // dangling Ref that no later stab will ever resolve.
                id.file == 0 && id.n < 0 -> TypeDecl.Builtin(id.n)

                // Forward reference
                else -> TypeDecl.Ref(id)
            }
        }

        else -> throw StabsParseException(pos, src, "unexpected character '$ch' in type descriptor")
    }

    // ===== Type productions =====

    /**
     * Parse a struct/union/class body.
     * Format: `<size>[!<inheritance>]<fields-and-methods>;[~%<vptr-owner-id>;]`
     *
     * Mirror of gdb/stabsread.c:read_struct_type. The `~%` tilde field is the LAST section,
     * after member functions — not after inheritance (read_tilde_fields runs last).
     */
    private fun Cursor.parseStruct(kind: AggrKind): TypeDecl.Struct<LocalTypeId> {
        val sizeBytes = readInt()

        // Parse optional inheritance section
        val bases = if (consumeIf('!')) {
            parseInheritanceList()
        } else {
            emptyList()
        }

        // Parse fields and methods.
        // Each field is terminated by ';'. The list itself is terminated by a bare ';'
        // (so the struct ends with field-terminator + struct-terminator = ";;").
        // After consuming each field's ';', peek: if the next char is ';' that's the
        // struct terminator — exit without consuming it (consumed below).
        val fields = mutableListOf<Field<LocalTypeId>>()
        val methods = mutableListOf<Method<LocalTypeId>>()

        while (peekOrNull() != ';' && !eof) {
            val name = readMemberName()

            when {
                peekFollows("::") -> {
                    // Method: name::<overload1>[<overload2>...];
                    // GCC emits multiple overloads consecutively: after each overload's virt
                    // char (without a trailing ';'), the next overload TypeId follows immediately.
                    advance()
                    advance()
                    methods.add(parseMethodBlock(name))
                    while (peekStartsTypeId()) {
                        methods.add(parseMethodBlock(name))
                    }
                }

                peekFollows(":/") -> {
                    // Field with access specifier: name:/<access><type>...
                    // Static:     name:/<access><type>:<mangled>;
                    // Non-static: name:/<access><type>,<offset>,<size>;
                    advance()
                    advance()
                    val access = accessOf(if (!eof) advance() else '2')
                    val type = parseType()
                    if (peekOrNull() == ',') {
                        consume(',')
                        val offsetBits = readInt()
                        consume(',')
                        val sizeBits = readInt()
                        consume(';')
                        // `,0,0` shape is static here too (see the plain `:` branch below).
                        val isStatic = offsetBits == 0L && sizeBits == 0L
                        fields.add(Field(name, type, offsetBits, sizeBits, isStatic, access, mangled = null))
                    } else {
                        consume(':')
                        val mangled = readUntilAny(charArrayOf(';'))
                        consume(';')
                        fields.add(Field(name, type, 0, 0, isStatic = true, access, mangled))
                    }
                }

                peekFollows(":") -> {
                    // Normal field: name:<type>,<offset>,<size>;
                    advance()
                    val type = parseType()
                    consume(',')
                    val offsetBits = readInt()
                    consume(',')
                    val sizeBits = readInt()
                    consume(';')
                    // Without -gstabs+, gcc emits a static data member (a VAR_DECL) as `,0,0`
                    // instead of the `:mangled` form; offset-and-size both zero is a shape a
                    // real field can't take, so it marks the member static.
                    val isStatic = offsetBits == 0L && sizeBits == 0L
                    fields.add(Field(name, type, offsetBits, sizeBits, isStatic, Access.PUBLIC, mangled = null))
                }

                peekFollows("/") -> {
                    // Static field starting with /
                    advance()
                    val access = accessOf(if (!eof) advance() else '2')
                    val type = parseType()
                    consume(':')
                    val mangled = readUntilAny(charArrayOf(';'))
                    consume(';')
                    fields.add(Field(name, type, 0, 0, isStatic = true, access, mangled))
                }

                else -> {
                    throw StabsParseException(pos, src, "unexpected character in struct field")
                }
            }
        }

        consume(';') // struct terminator

        // Trailing tilde field `~%<type>;` — vptr-owning base of a polymorphic class. The target is a
        // full read_type (gdb read_tilde_fields): a bare ref, or an inline forward-xref for RTTI classes.
        val vptrBasetype = if (consumeIf('~')) {
            consume('%')
            parseType().also { consume(';') }
        } else {
            null
        }

        // A fully-consumed struct is followed only by a boundary: symbol/field/base terminator
        // or eof. Anything else is an unparsed section (the bug that hid `~%` for years).
        if (peekOrNull()?.let { it !in BOUNDARY_CHARS } == true) {
            throw StabsParseException(pos, src, "unconsumed struct section")
        }

        return TypeDecl.Struct(
            rawKind = kind,
            sizeBytes = sizeBytes,
            bases = bases,
            fields = fields,
            methods = methods,
            vptrBasetype = vptrBasetype,
        )
    }

    /**
     * Parse inheritance list after `!`.
     * Format: `<count>,<base-list>;`
     * Each base: `<virt><access><offset>,<base-id>;`
     *
     * Mirror of gdb/stabsread.c:read_cpp_abbrev.
     */
    private fun Cursor.parseInheritanceList(): List<Base<LocalTypeId>> {
        val count = readInt().toInt()
        consume(',')

        return buildList {
            repeat(count) {
                val virt = advance() == '1'
                val access = accessOf(advance())
                val offsetBits = readInt()
                consume(',')
                val baseType = parseType() // handles (cu,n) ref and (cu,n)=<inline-def> forms
                consume(';')
                add(Base(baseType, virt, access, offsetBits))
            }
        }
    }

    /**
     * Parse a method block (after `::` in struct).
     * GCC 3.4.4 format: `(cu,n)[=#cls,ret,p1,...,pN;]:mangled;<access><modifier><virt>[*<voff>;<vthistype>;]`
     *
     * The type-id is parsed via parseType() which handles both the inline-definition form
     * `(cu,n)=<type>` and the back-reference form `(cu,n)`.
     *
     * Mirror of gdb/stabsread.c:read_member_functions.
     */
    private fun Cursor.parseMethodBlock(name: String): Method<LocalTypeId> {
        val signature = parseType()

        val mangled = if (!eof && peekOrNull() == ':') {
            advance()
            val mangledName = readUntilAny(charArrayOf(';'))
            consume(';')
            mangledName
        } else {
            null
        }

        val access = accessOf(if (!eof && peekOrNull()?.isDigit() == true) advance() else '2')
        // cv-qualifier letter: A none, B const, C volatile, D const volatile.
        val modifier = if (!eof) advance() else 'A'
        val isConst = modifier == 'B' || modifier == 'D'
        val isVolatile = modifier == 'C' || modifier == 'D'

        var vtableOffsetBits: Long? = null
        val virt = when {
            peekOrNull() == '*' -> {
                advance()
                vtableOffsetBits = readInt()
                consume(';')
                parseType() // vthistype (consumed, not stored)
                consume(';')
                VirtKind.VIRTUAL
            }

            peekOrNull() == '.' -> {
                advance()
                VirtKind.NORMAL
            }

            // `?` is a *static* member function (stabsread.c `case '?'`), not a pure virtual —
            // its signature is a plain `f(ret)` rather than a `#(cls,…)` method type, and it
            // takes no `this`. gcc has no distinct marker for pure virtuals; they ride `*`.
            peekOrNull() == '?' -> {
                advance()
                VirtKind.STATIC
            }

            else -> VirtKind.NORMAL
        }

        consumeIf(';')

        return Method(
            name = name,
            mangled = mangled,
            signature = signature,
            access = access,
            virt = virt,
            isConst = isConst,
            isVolatile = isVolatile,
            vtableOffsetBits = vtableOffsetBits,
        )
    }

    /**
     * Parse an enum body. Format: `<name>:<value>,<name>:<value>,...;`. Mirror of
     * gdb/stabsread.c:read_enum_type, except for bool — see [boolOrEnum].
     */
    private fun Cursor.parseEnum(): TypeDecl<LocalTypeId> = boolOrEnum(parseEnumBody())

    /**
     * Classic stabs has no boolean descriptor, so without `-gstabs+` gcc cannot record bool's width
     * at all — `gcc/dbxout.c`:
     *
     * ```
     * case BOOLEAN_TYPE:
     *   if (use_gnu_debug_info_extensions) { "@s" <BITS_PER_UNIT * int_size_in_bytes(type)> ";-16;" }
     *   else / * Define as enumeral type (False, True) * / "eFalse:0,True:1,;"
     * ```
     *
     * Both branches describe the same BOOLEAN_TYPE, so decode the fallback to what the extension
     * branch would have written. Left as an enum it takes sizeof(int) — as it does in gdb's
     * read_enum_type, which sets the length unconditionally — and a 1-byte bool global then swallows
     * the three after it.
     *
     * Keyed on the members, not the name: gcc emits this literal wherever a bool appears, including
     * unnamed and inline (xmltest carries both `bool:t(0,9)=eFalse:0,True:1,;` and a bare
     * `(0,8)=eFalse:0,True:1,;` as a return type). Converting only the named one orphans the other
     * from the content merge that had been giving it the name. The cost is that a hand-written
     * `enum Flag { False, True }` decodes to bool too — gcc's spelling is identical to it — and this
     * way at least every occurrence agrees rather than half of them.
     */
    private fun boolOrEnum(body: TypeDecl.Enum<LocalTypeId>): TypeDecl<LocalTypeId> =
        if (body.members == BOOL_ENUM_MEMBERS) {
            TypeDecl.WithSizeAttr(BITS_PER_BYTE, TypeDecl.Builtin(BUILTIN_BOOL))
        } else {
            body
        }

    private fun Cursor.parseEnumBody() = TypeDecl.Enum<LocalTypeId>(
        buildList {
            consume('e')

            while (!peekFollows(";") && !eof) {
                val name = readUntilAny(charArrayOf(':'))
                consume(':')
                val value = readInt()
                consumeIf(',')
                add(Pair(name, value))
            }

            consume(';')
        },
    )

    /**
     * Parse a range type: `r<id>;<min>;<max>;`
     * Bounds may be in decimal or octal (with leading 0).
     *
     * Returns `TypeDecl.Float` for the gcc float encoding `r<base>;<NBYTES>;0;`
     * (i.e. `min > 0 && max == 0`) where `<base>` is decorative per the stabs
     * spec — see [TypeDecl.Float] kdoc. Otherwise returns [TypeDecl.Range].
     *
     * Mirror of gdb/stabsread.c:read_range_type.
     */
    private fun Cursor.parseRange(): TypeDecl<LocalTypeId> {
        consume('r')
        val typeId = readTypeId()
        // GCC may define the base type inline: r(cu,n)=<inner-type>;lo;hi;
        if (consumeIf('=')) {
            parseType() // parse and discard the inline base-type definition
        }
        consume(';')
        val min = readRangeBound()
        consume(';')
        val max = readRangeBound()
        consume(';')
        if (max == 0L && min > 0L) {
            return TypeDecl.Float(min)
        }
        return TypeDecl.Range(typeId, min, max)
    }

    /**
     * Parse a complex type: `R<n>;<size>;0;`
     * n encodes type (3=cfloat, 4=cdouble, 5=cldouble per gcc/dbxout.c).
     *
     * Mirror of gcc/dbxout.c:dbxout_type (COMPLEX_TYPE case).
     */
    private fun Cursor.parseComplex(): TypeDecl.Complex<LocalTypeId> {
        consume('R')
        val rCode = readInt().toInt()
        consume(';')
        val sizeBytes = readInt()
        consume(';')
        consume('0')
        consume(';')
        return TypeDecl.Complex(rCode, sizeBytes)
    }

    /**
     * Parse a cross-reference: `x<kind><name>:`
     * Kind: 's'=struct, 'u'=union, 'c'=class, 'Y'=class (gcc-2 form).
     *
     * Mirror of gdb/stabsread.c:read_cross_ref and stabs.html §4.6.
     */
    private fun Cursor.parseXRef(): TypeDecl.XRef<LocalTypeId> {
        consume('x')
        val kind = when (val kindChar = advance()) {
            's' -> AggrKind.STRUCT
            'u' -> AggrKind.UNION
            'e' -> AggrKind.ENUM
            'c', 'Y' -> AggrKind.CLASS
            else -> throw StabsParseException(pos - 1, src, "unknown cross-ref kind '$kindChar'")
        }
        val tagName = readXRefTagName() // skips :: inside <>, stops at single ':' at depth 0
        consume(':')
        return TypeDecl.XRef(kind, tagName)
    }

    /**
     * Parse a size attribute: `@s<n>;<inner>`
     * The `n` is in bits; the inner type is parsed recursively.
     *
     * Mirror of gcc/dbxout.c:dbxout_type (size-attribute emission).
     */
    private fun Cursor.parseSizeAttr(): TypeDecl.WithSizeAttr<LocalTypeId> {
        consume('@')
        consume('s')
        val sizeBits = readInt()
        consume(';')
        val inner = parseType()
        return TypeDecl.WithSizeAttr(sizeBits, inner)
    }

    /**
     * Parse an array: `a<index-type>;<element-type>`
     * Optionally followed by a range of valid indices.
     *
     * Mirror of gdb/stabsread.c:read_array_type.
     */
    private fun Cursor.parseArray(): TypeDecl.Array<LocalTypeId> {
        consume('a')
        val indexType = parseType()
        // parseRange (the typical index type) already consumes its own trailing ';',
        // so NO separator between index type and element type.
        val elementType = parseType()
        return TypeDecl.Array(elementType, null, indexType)
    }

    /**
     * Parse a function type: `f<return-type>`
     * Note: stabs function descriptors typically don't carry parameter types in the type itself;
     * parameters come via separate `:p`/`:P` records. The Method (#) form DOES carry params.
     *
     * Mirror of gdb/stabsread.c:read_type (f case).
     */
    private fun Cursor.parseFunctionT(): TypeDecl.FunctionT<LocalTypeId> {
        consume('f')
        val retType = parseType()
        return TypeDecl.FunctionT(retType, emptyList())
    }

    /**
     * Parse a pointer-to-member-function: `#<cls>,<ret>;<params>;`
     * Method (#) descriptors carry parameter types inline.
     *
     * Mirror of gdb/stabsread.c:read_type (# case) and gdb/stabsread.c:read_member_functions.
     */
    private fun Cursor.parseMethod(): TypeDecl.Method<LocalTypeId> {
        consume('#')
        val clsType = parseType()
        consume(',')
        val retType = parseType()

        val params = mutableListOf<TypeDecl<LocalTypeId>>()
        while (consumeIf(',')) {
            params.add(parseType())
        }

        consume(';')
        return TypeDecl.Method(clsType, retType, params)
    }

    // ===== Lexical token readers (Cursor extensions) =====

    /** Read `(cu,n)` or bare `n`. */
    private fun Cursor.readTypeId(): LocalTypeId {
        if (consumeIf('(')) {
            val cu = readInt().toInt()
            consume(',')
            val n = readInt().toInt()
            consume(')')
            return LocalTypeId(cu, n)
        }
        val n = readInt().toInt()
        return LocalTypeId(0, n)
    }

    /** True at the start of a type-id: `(cu,n)`, a bare `n`, or a negative builtin `-n`. */
    private fun Cursor.peekStartsTypeId(): Boolean =
        peekOrNull()?.let { it == '(' || it == '-' || it.isDigit() } == true

    /** Read up to the descriptor `:`. `::` (C++ scope) is preserved; only a single `:` terminates. */
    private fun Cursor.readSymbolName() = StringBuilder().apply {
        while (!eof) {
            if (src[pos] == ':') {
                if (peekOrNull(1) == ':') feed(2) else break
            } else {
                feed()
            }
        }
    }.toString()

    /**
     * Read a struct member / base-class name up to the terminating `:` or `/` at template
     * depth 0. Two wrinkles gcc emits inside such names:
     *  - a base class spelled out as a pseudo-field carries qualified template args, e.g.
     *    `AllocatorBase<CryptoPP::word16>` — the `::` there is part of the name, not a
     *    method marker, so `::` inside `<...>` is consumed;
     *  - `operator<`, `operator<<`, `operator>=`, … keep their angle brackets as operator
     *    tokens rather than opening template depth (they are unbalanced otherwise).
     */
    private fun Cursor.readMemberName() = StringBuilder().apply {
        var depth = 0
        while (!eof) {
            when (src[pos]) {
                '<' -> {
                    feed()
                    depth++
                }

                '>' -> {
                    feed()
                    if (depth > 0) depth--
                }

                ':' if depth > 0 && peekOrNull(1) == ':' -> feed(2)

                ':' -> break

                '/' if depth == 0 -> break

                else if depth == 0 &&
                    peekFollows("operator") &&
                    peekOrNull(8)?.let { it in OPERATOR_SYMBOLS } == true -> {
                    feed(8)
                    while (!eof && src[pos] in OPERATOR_SYMBOLS) feed()
                }

                else -> feed()
            }
        }
        // gcc spells its special-member pseudo-names with a space before `::`
        // (`__comp_dtor ::`, `__base_dtor ::`); drop the trailing space so the name matches
        // between the vtable field and its function-pointer type.
    }.toString().trimEnd()

    /** Read an XRef tag name. `::` is preserved only inside `<>` template-arg depth > 0. */
    private fun Cursor.readXRefTagName() = StringBuilder().apply {
        var depth = 0
        while (!eof) {
            when (src[pos]) {
                '<' -> {
                    feed()
                    depth++
                }

                '>' -> {
                    feed()
                    if (depth > 0) depth--
                }

                ':' if peekOrNull(1) == ':' && depth > 0 -> feed(2)

                // single `:` or `::` at depth 0
                ':' -> break

                else -> feed()
            }
        }
    }.toString()

    // ===== Helpers =====

    /**
     * Parse an access specifier: 0=private, 1=protected, 2=public.
     */
    private fun accessOf(ch: Char): Access = when (ch) {
        '0' -> Access.PRIVATE
        '1' -> Access.PROTECTED
        '2' -> Access.PUBLIC
        else -> Access.PUBLIC // default
    }
}
