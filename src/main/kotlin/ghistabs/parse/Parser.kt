package ghistabs.parse

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
    private val c = Cursor(src)

    /**
     * Parse a symbol declaration: `name:descriptor` where descriptor may be
     * a single letter (F/f/p/P/r/G/S/V/T/t) followed by type body, or no letter
     * (stack local).
     *
     * Mirror of gdb/stabsread.c:define_symbol.
     */
    fun parseSymbol(): SymbolDecl<LocalTypeId> {
        val name = c.readSymbolName()
        c.consume(':')
        val descriptor = c.peekOrNull()

        return when (descriptor) {
            'F' -> {
                c.advance()
                SymbolDecl.Function(name, isFileStatic = false, type = parseType())
            }

            'f' -> {
                c.advance()
                SymbolDecl.Function(name, isFileStatic = true, type = parseType())
            }

            'p' -> {
                c.advance()
                SymbolDecl.StackParam(name, parseType())
            }

            'P' -> {
                c.advance()
                SymbolDecl.RegParam(name, parseType(), regNum = readTrailingReg())
            }

            'r' -> {
                c.advance()
                SymbolDecl.RegLocal(name, parseType(), regNum = readTrailingReg())
            }

            'G' -> {
                c.advance()
                SymbolDecl.Global(name, parseType())
            }

            'S' -> {
                c.advance()
                SymbolDecl.StaticVar(name, parseType(), isFunctionLocal = false)
            }

            'V' -> {
                c.advance()
                SymbolDecl.StaticVar(name, parseType(), isFunctionLocal = true)
            }

            'T' -> parseTagged(name)

            't' -> parseTypedef(name)

            else -> SymbolDecl.StackLocal(name, parseType())
        }
    }

    /**
     * Parse a type descriptor body, exposed for testing.
     */
    fun parseTypeBody(): TypeDecl<LocalTypeId> = parseType()

    // ===== Symbol-level productions =====

    /**
     * Parse `:T(cu,n)=<body>` (tagged type), or the body-less forward-
     * declaration form `:T(cu,n)` that gcc emits when the tag is named
     * here but its body is defined by a later stab. Mirror of
     * `gdb/stabsread.c:define_symbol` (T case).
     */
    private fun parseTagged(name: String): SymbolDecl.TaggedType<LocalTypeId> {
        c.consume('T')
        c.consumeIf('t') // GCC emits Tt for combined tagged-type+typedef (e.g. typedef struct foo {} foo)
        val id = c.parseTypeId()
        val body = if (c.consumeIf('=')) parseType() else TypeDecl.Ref(id)
        return SymbolDecl.TaggedType(name, id, body)
    }

    /**
     * Parse `:t(cu,n)=<body>` (typedef), or the body-less forward-
     * declaration form `:t(cu,n)` (the binding for the body lives in a
     * separate stab — common with cygwin gcc 13+ on box2d-style C++23
     * code). Mirror of `gdb/stabsread.c:define_symbol` (t case).
     */
    private fun parseTypedef(name: String): SymbolDecl.Typedef<LocalTypeId> {
        c.consume('t')
        val id = c.parseTypeId()
        val body = if (c.consumeIf('=')) parseType() else TypeDecl.Ref(id)
        return SymbolDecl.Typedef(name, id, body)
    }

    // ===== Type descriptor dispatch =====

    /**
     * Parse a type descriptor by lookahead character.
     * Dispatches to specific productions: Pointer (*), Reference (&), Const (k),
     * Volatile (B), Array (a), Enum (e), Struct (s/u/Y), FunctionT (f), Method (#),
     * Range (r), Complex (R), XRef (x), WithSizeAttr (@), or forward reference.
     *
     * Mirror of gdb/stabsread.c:read_type.
     */
    private fun parseType(): TypeDecl<LocalTypeId> = when (val ch = c.peekOrNull()) {
        'a' -> parseArray()

        'e' -> parseEnum()

        'f' -> parseFunctionT()

        '#' -> parseMethod()

        'r' -> parseRange()

        'R' -> parseComplex()

        'x' -> parseXRef()

        '@' -> parseSizeAttr()

        '*' -> {
            c.advance()
            TypeDecl.Pointer(parseType())
        }

        '&' -> {
            c.advance()
            TypeDecl.Reference(parseType())
        }

        'k' -> {
            c.advance()
            TypeDecl.Const(parseType())
        }

        'B' -> {
            c.advance()
            TypeDecl.Volatile(parseType())
        }

        's' -> {
            c.advance()
            parseStruct(AggrKind.STRUCT)
        }

        'u' -> {
            c.advance()
            parseStruct(AggrKind.UNION)
        }

        'Y' -> {
            c.advance()
            parseStruct(AggrKind.CLASS)
        }

        else if (ch == '(' || ch == '-' || ch?.isDigit() == null) -> {
            // Forward reference, inline definition, or builtin slot: (cu,n) /
            // bare n, possibly followed by =.
            val id = c.parseTypeId()
            when {
                // Inline definition: parse the body recursively and wrap in InlineDef
                c.consumeIf('=') -> TypeDecl.InlineDef(id, parseType())

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

        else -> throw StabsParseException(c.pos, c.src, "unexpected character '$ch' in type descriptor")
    }

    // ===== Type productions =====

    /**
     * Parse a struct/union/class body.
     * Format: `<size>[!<inheritance>][~%<vtable-id>;]<fields-and-methods>;;`
     *
     * Mirror of gdb/stabsread.c:read_struct_type.
     */
    private fun parseStruct(kind: AggrKind): TypeDecl.Struct<LocalTypeId> {
        val sizeBytes = c.parseInt()

        // Parse optional inheritance section
        val bases = if (c.consumeIf('!')) {
            parseInheritanceList()
        } else {
            emptyList()
        }

        // Parse optional vtable pointer marker
        val (hasVTablePointer, vtableTypeId) = if (c.consumeIf('~')) {
            c.consume('%')
            val id = c.parseTypeId()
            c.consume(';')
            Pair(true, id)
        } else {
            Pair(false, null)
        }

        // Parse fields and methods.
        // Each field is terminated by ';'. The list itself is terminated by a bare ';'
        // (so the struct ends with field-terminator + struct-terminator = ";;").
        // After consuming each field's ';', peek: if the next char is ';' that's the
        // struct terminator — exit without consuming it (consumed below).
        val fields = mutableListOf<FieldDecl<LocalTypeId>>()
        val methods = mutableListOf<MethodDecl<LocalTypeId>>()

        while (c.peekOrNull() != ';' && !c.eof) {
            val name = c.readUntilAny(charArrayOf(':', '/'))

            when {
                c.startsWith("::") -> {
                    // Method: name::<overload1>[<overload2>...];
                    // GCC emits multiple overloads consecutively: after each overload's virt
                    // char (without a trailing ';'), the next overload TypeId follows immediately.
                    c.advance()
                    c.advance()
                    methods.add(parseMethodBlock(name))
                    while (c.peekOrNull().let { it == '(' || (it != null && it.isDigit()) }) {
                        methods.add(parseMethodBlock(name))
                    }
                }

                c.startsWith(":/") -> {
                    // Field with access specifier: name:/<access><type>...
                    // Static:     name:/<access><type>:<mangled>;
                    // Non-static: name:/<access><type>,<offset>,<size>;
                    c.advance()
                    c.advance()
                    val access = parseAccess(if (!c.eof) c.advance() else '2')
                    val type = parseType()
                    if (c.peekOrNull() == ',') {
                        c.consume(',')
                        val offsetBits = c.parseInt()
                        c.consume(',')
                        val sizeBits = c.parseInt()
                        c.consume(';')
                        fields.add(FieldDecl(name, type, offsetBits, sizeBits, isStatic = false))
                    } else {
                        c.consume(':')
                        c.readUntilAny(charArrayOf(';')) // mangled symbol; discarded — captured by COFF symbol table
                        c.consume(';')
                        fields.add(FieldDecl(name, type, 0, 0, isStatic = true))
                    }
                }

                c.startsWith(":") -> {
                    // Normal field: name:<type>,<offset>,<size>;
                    c.advance()
                    val type = parseType()
                    c.consume(',')
                    val offsetBits = c.parseInt()
                    c.consume(',')
                    val sizeBits = c.parseInt()
                    c.consume(';')
                    fields.add(FieldDecl(name, type, offsetBits, sizeBits, isStatic = false))
                }

                c.startsWith("/") -> {
                    // Static field starting with /
                    c.advance()
                    val access = parseAccess(if (!c.eof) c.advance() else '2')
                    val type = parseType()
                    c.consume(':')
                    c.readUntilAny(charArrayOf(';')) // mangled symbol; discarded — captured by COFF symbol table
                    c.consume(';')
                    fields.add(FieldDecl(name, type, 0, 0, isStatic = true))
                }

                else -> {
                    throw StabsParseException(c.pos, c.src, "unexpected character in struct field")
                }
            }
        }

        c.consume(';') // struct terminator

        return TypeDecl.Struct(
            kind = kind,
            sizeBytes = sizeBytes,
            bases = bases,
            fields = fields,
            methods = methods,
            hasVTablePointerMarker = hasVTablePointer,
            vtableTargetTypeId = vtableTypeId,
        )
    }

    /**
     * Parse inheritance list after `!`.
     * Format: `<count>,<base-list>;`
     * Each base: `<virt><access><offset>,<base-id>;`
     *
     * Mirror of gdb/stabsread.c:read_cpp_abbrev.
     */
    private fun parseInheritanceList(): List<BaseDecl<LocalTypeId>> {
        val count = c.parseInt().toInt()
        c.consume(',')

        val bases = mutableListOf<BaseDecl<LocalTypeId>>()
        repeat(count) {
            val virt = c.advance() == '1'
            val access = parseAccess(c.advance())
            val offsetBits = c.parseInt()
            c.consume(',')
            val baseType = parseType() // handles (cu,n) ref and (cu,n)=<inline-def> forms
            c.consume(';')
            bases.add(BaseDecl(baseType, virt, access, offsetBits))
        }

        return bases
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
    private fun parseMethodBlock(name: String): MethodDecl<LocalTypeId> {
        val signature = parseType()

        val mangled = if (!c.eof && c.peekOrNull() == ':') {
            c.advance()
            val mangledName = c.readUntilAny(charArrayOf(';'))
            c.consume(';')
            mangledName
        } else {
            null
        }

        val access = parseAccess(if (!c.eof && c.peekOrNull()?.isDigit() == true) c.advance() else '2')
        val modifier = if (!c.eof) c.advance() else 'A'
        val isConst = modifier == 'C'
        val isVolatile = modifier == 'V'

        var vtableOffsetBits: Long? = null
        val virt = when {
            c.peekOrNull() == '*' -> {
                c.advance()
                vtableOffsetBits = c.parseInt()
                c.consume(';')
                parseType() // vthistype (consumed, not stored)
                c.consume(';')
                VirtKind.VIRTUAL
            }

            c.peekOrNull() == '.' -> {
                c.advance()
                VirtKind.NORMAL
            }

            c.peekOrNull() == '?' -> {
                c.advance()
                VirtKind.PURE_VIRTUAL
            }

            else -> VirtKind.NORMAL
        }

        c.consumeIf(';')

        return MethodDecl(
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
     * Parse an enum body.
     * Format: `<name>:<value>,<name>:<value>,...;`
     *
     * Mirror of gdb/stabsread.c:read_enum_type.
     */
    private fun parseEnum(): TypeDecl.Enum<LocalTypeId> {
        c.consume('e')
        val members = mutableListOf<Pair<String, Long>>()

        while (!c.startsWith(";") && !c.eof) {
            val name = c.readUntilAny(charArrayOf(':'))
            c.consume(':')
            val value = c.parseInt()
            c.consumeIf(',')
            members.add(Pair(name, value))
        }

        c.consume(';')
        return TypeDecl.Enum(members)
    }

    /**
     * Parse a range type: `r<id>;<min>;<max>;`
     * Bounds may be in decimal or octal (with leading 0).
     *
     * Mirror of gdb/stabsread.c:read_range_type.
     */
    private fun parseRange(): TypeDecl.Range<LocalTypeId> {
        c.consume('r')
        val typeId = c.parseTypeId()
        // GCC may define the base type inline: r(cu,n)=<inner-type>;lo;hi;
        if (c.consumeIf('=')) {
            parseType() // parse and discard the inline base-type definition
        }
        c.consume(';')
        val min = c.parseRangeBound()
        c.consume(';')
        val max = c.parseRangeBound()
        c.consume(';')
        return TypeDecl.Range(typeId, min, max)
    }

    /**
     * Parse a complex type: `R<n>;<size>;0;`
     * n encodes type (3=cfloat, 4=cdouble, 5=cldouble per gcc/dbxout.c).
     *
     * Mirror of gcc/dbxout.c:dbxout_type (COMPLEX_TYPE case).
     */
    private fun parseComplex(): TypeDecl.Complex<LocalTypeId> {
        c.consume('R')
        val rCode = c.parseInt().toInt()
        c.consume(';')
        val sizeBytes = c.parseInt().toInt()
        c.consume(';')
        c.consume('0')
        c.consume(';')
        return TypeDecl.Complex(rCode, sizeBytes)
    }

    /**
     * Parse a cross-reference: `x<kind><name>:`
     * Kind: 's'=struct, 'u'=union, 'c'=class, 'Y'=class (gcc-2 form).
     *
     * Mirror of gdb/stabsread.c:read_cross_ref and stabs.html §4.6.
     */
    private fun parseXRef(): TypeDecl.XRef<LocalTypeId> {
        c.consume('x')
        val kind = when (val kindChar = c.advance()) {
            's' -> AggrKind.STRUCT
            'u' -> AggrKind.UNION
            'e' -> AggrKind.ENUM
            'c', 'Y' -> AggrKind.CLASS
            else -> throw StabsParseException(c.pos - 1, c.src, "unknown cross-ref kind '$kindChar'")
        }
        val tagName = c.readXRefTagName() // skips :: inside <>, stops at single ':' at depth 0
        c.consume(':')
        return TypeDecl.XRef(kind, tagName)
    }

    /**
     * Parse a size attribute: `@s<n>;<inner>`
     * The `n` is in bits; the inner type is parsed recursively.
     *
     * Mirror of gcc/dbxout.c:dbxout_type (size-attribute emission).
     */
    private fun parseSizeAttr(): TypeDecl.WithSizeAttr<LocalTypeId> {
        c.consume('@')
        c.consume('s')
        val sizeBits = c.parseInt().toInt()
        c.consume(';')
        val inner = parseType()
        return TypeDecl.WithSizeAttr(sizeBits, inner)
    }

    /**
     * Parse an array: `a<index-type>;<element-type>`
     * Optionally followed by a range of valid indices.
     *
     * Mirror of gdb/stabsread.c:read_array_type.
     */
    private fun parseArray(): TypeDecl.Array<LocalTypeId> {
        c.consume('a')
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
    private fun parseFunctionT(): TypeDecl.FunctionT<LocalTypeId> {
        c.consume('f')
        val retType = parseType()
        return TypeDecl.FunctionT(retType, emptyList())
    }

    /**
     * Parse a pointer-to-member-function: `#<cls>,<ret>;<params>;`
     * Method (#) descriptors carry parameter types inline.
     *
     * Mirror of gdb/stabsread.c:read_type (# case) and gdb/stabsread.c:read_member_functions.
     */
    private fun parseMethod(): TypeDecl.Method<LocalTypeId> {
        c.consume('#')
        val clsType = parseType()
        c.consume(',')
        val retType = parseType()

        val params = mutableListOf<TypeDecl<LocalTypeId>>()
        while (c.consumeIf(',')) {
            params.add(parseType())
        }

        c.consume(';')
        return TypeDecl.Method(clsType, retType, params)
    }

    // ===== Helpers =====

    /**
     * Parse an access specifier: 0=private, 1=protected, 2=public.
     */
    private fun parseAccess(ch: Char): Access = when (ch) {
        '0' -> Access.PRIVATE
        '1' -> Access.PROTECTED
        '2' -> Access.PUBLIC
        else -> Access.PUBLIC // default
    }

    /**
     * Read a trailing register number (after `:P`, `:r`, etc.).
     * Format: type-info followed by `;` and register number.
     *
     * Register number comes from n_value in the stab record, not the descriptor string.
     */
    private fun readTrailingReg(): Int = 0
}
