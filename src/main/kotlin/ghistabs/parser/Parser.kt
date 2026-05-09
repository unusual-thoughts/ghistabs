package ghistabs.parser

/**
 * Recursive-descent parser for stabs type and symbol descriptors.
 * Implements Sun + GCC stabs grammar as emitted by Cygwin gcc 3.4.4.
 *
 * Entry points:
 * - [parseSymbol]: Parse a `name:descriptor` symbol declaration.
 * - [parseTypeBody]: Parse a type descriptor (used internally and by tests).
 *
 * All other methods are private productions — one method per grammar rule.
 */
class Parser(
    src: String,
) {
    private val c = Cursor(src)

    /**
     * Parse a symbol declaration: `name:descriptor` where descriptor may be
     * a single letter (F/f/p/P/r/G/S/V/T/t) followed by type body, or no letter
     * (stack local).
     *
     * Mirror of gdb/stabsread.c:define_symbol.
     */
    fun parseSymbol(): SymbolDecl {
        val name = c.readUntilAny(charArrayOf(':'))
        c.consume(':')
        val descriptor = c.peekOrNull()

        return when (descriptor) {
            'F' -> {
                c.advance()
                SymbolDecl.Function(name, isFileStatic = false, signature = parseType())
            }

            'f' -> {
                c.advance()
                SymbolDecl.Function(name, isFileStatic = true, signature = parseType())
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

            'T' -> {
                parseTagged(name)
            }

            't' -> {
                parseTypedef(name)
            }

            else -> {
                SymbolDecl.StackLocal(name, parseType())
            }
        }
    }

    /**
     * Parse a type descriptor body, exposed for testing.
     */
    fun parseTypeBody(): TypeDecl = parseType()

    // ===== Symbol-level productions =====

    /**
     * Parse `:T(cu,n)=<body>` (tagged type).
     * Mirror of gdb/stabsread.c:define_symbol (T case).
     */
    private fun parseTagged(name: String): SymbolDecl.TaggedType {
        c.consume('T')
        val id = c.parseTypeId()
        c.consume('=')
        val body = parseType()
        return SymbolDecl.TaggedType(name, id, body)
    }

    /**
     * Parse `:t(cu,n)=<body>` (typedef).
     * Mirror of gdb/stabsread.c:define_symbol (t case).
     */
    private fun parseTypedef(name: String): SymbolDecl.Typedef {
        c.consume('t')
        val id = c.parseTypeId()
        c.consume('=')
        val body = parseType()
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
    private fun parseType(): TypeDecl {
        val ch = c.peekOrNull()

        return when {
            ch == '*' -> {
                c.advance()
                TypeDecl.Pointer(parseType())
            }

            ch == '&' -> {
                c.advance()
                TypeDecl.Reference(parseType())
            }

            ch == 'k' -> {
                c.advance()
                TypeDecl.Const(parseType())
            }

            ch == 'B' -> {
                c.advance()
                TypeDecl.Volatile(parseType())
            }

            ch == 'a' -> {
                parseArray()
            }

            ch == 'e' -> {
                parseEnum()
            }

            ch == 's' -> {
                c.advance()
                parseStruct(AggrKind.STRUCT)
            }

            ch == 'u' -> {
                c.advance()
                parseStruct(AggrKind.UNION)
            }

            ch == 'Y' -> {
                c.advance()
                parseStruct(AggrKind.CLASS)
            }

            ch == 'f' -> {
                parseFunctionT()
            }

            ch == '#' -> {
                parseMethod()
            }

            ch == 'r' -> {
                parseRange()
            }

            ch == 'R' -> {
                parseComplex()
            }

            ch == 'x' -> {
                parseXRef()
            }

            ch == '@' -> {
                parseSizeAttr()
            }

            ch == '(' || (ch != null && (ch.isDigit() || ch == '-')) -> {
                // Forward reference or inline definition: (cu,n) or bare n, possibly followed by =
                val saved = c.snapshot()
                val id = c.parseTypeId()
                if (c.consumeIf('=')) {
                    // Inline definition: parse the body recursively
                    parseType()
                } else {
                    // Forward reference
                    TypeDecl.Ref(id)
                }
            }

            else -> {
                throw StabsParseException(c.pos, c.src, "unexpected character '$ch' in type descriptor")
            }
        }
    }

    // ===== Type productions =====

    /**
     * Parse a struct/union/class body.
     * Format: `<size>[!<inheritance>][~%<vtable-id>;]<fields-and-methods>;;`
     *
     * Mirror of gdb/stabsread.c:read_struct_type.
     */
    private fun parseStruct(kind: AggrKind): TypeDecl.Struct {
        val sizeBytes = c.parseInt()

        // Parse optional inheritance section
        val bases =
            if (c.consumeIf('!')) {
                parseInheritanceList()
            } else {
                emptyList()
            }

        // Parse optional vtable pointer marker
        val (hasVTablePointer, vtableTypeId) =
            if (c.consumeIf('~')) {
                c.consume('%')
                val id = c.parseTypeId()
                c.consume(';')
                Pair(true, id)
            } else {
                Pair(false, null)
            }

        // Parse fields and methods until ;;
        val fields = mutableListOf<FieldDecl>()
        val methods = mutableListOf<MethodDecl>()

        while (!c.startsWith(";;")) {
            if (c.eof) throw StabsParseException(c.pos, c.src, "unexpected eof parsing struct fields")

            val name = c.readUntilAny(charArrayOf(':', '/'))

            when {
                c.startsWith("::") -> {
                    // Method: name::<method-block>;
                    c.advance()
                    c.advance()
                    val method = parseMethodBlock(name)
                    methods.add(method)
                }

                c.startsWith(":/") -> {
                    // Static field: name:/<access><type>:_Z...;
                    c.advance()
                    c.advance()
                    val access = parseAccess(if (!c.eof) c.advance() else '2')
                    val type = parseType()
                    c.consume(':')
                    val mangled = c.readUntilAny(charArrayOf(';'))
                    c.consume(';')
                    fields.add(FieldDecl(name, type, 0, 0, isStatic = true))
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
                    val mangled = c.readUntilAny(charArrayOf(';'))
                    c.consume(';')
                    fields.add(FieldDecl(name, type, 0, 0, isStatic = true))
                }

                else -> {
                    throw StabsParseException(c.pos, c.src, "unexpected character in struct field")
                }
            }
        }

        c.consume(';')
        c.consume(';')

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
    private fun parseInheritanceList(): List<BaseDecl> {
        val count = c.parseInt().toInt()
        c.consume(',')

        val bases = mutableListOf<BaseDecl>()
        repeat(count) {
            val virt = c.advance().toString()[0] == '1'
            val access = parseAccess(c.advance().toString()[0])
            val offsetBits = c.parseInt()
            c.consume(',')
            val baseTypeId = c.parseTypeId()
            c.consume(';')
            bases.add(BaseDecl(TypeDecl.Ref(baseTypeId), virt, access, offsetBits))
        }

        return bases
    }

    /**
     * Parse a method block (after `::` in struct).
     * Format: `(<count>=#<cls>,<ret>;<params>;):_Z<mangled>;<access><modifier><virt>[*<voff>;<vthistype>;]`
     *
     * Mirror of gdb/stabsread.c:read_member_functions.
     */
    private fun parseMethodBlock(name: String): MethodDecl {
        c.consume('(')
        val methodCount = c.parseInt()
        c.consume(')')
        c.consume('=')
        c.consume('#')
        val clsType = parseType()
        c.consume(',')
        val retType = parseType()
        c.consume(';')

        val paramTypes = mutableListOf<TypeDecl>()
        while (c.peekOrNull() != ')') {
            paramTypes.add(parseType())
            c.consumeIf(';')
        }

        c.consume(')')

        val mangled =
            if (c.startsWith(":_Z")) {
                c.advance() // consume :
                c.advance() // consume _
                c.advance() // consume Z
                val mangledName = c.readUntilAny(charArrayOf(';'))
                c.consume(';')
                "_Z" + mangledName
            } else {
                null
            }

        val access = parseAccess(if (!c.eof && c.peekOrNull()?.isDigit() == true) c.advance() else '2')
        val modifier = c.advance()
        val isConst = modifier == 'C'
        val isVolatile = modifier == 'V'

        var vtableOffsetBits: Long? = null
        val virt =
            when {
                c.peekOrNull() == '*' -> {
                    c.advance()
                    vtableOffsetBits = c.parseInt()
                    c.consume(';')
                    val vthistype = parseType()
                    c.consume(';')
                    VirtKind.VIRTUAL
                }

                c.peekOrNull() == '.' -> {
                    c.advance()
                    VirtKind.NORMAL
                }

                else -> {
                    VirtKind.NORMAL
                }
            }

        c.consumeIf(';')

        val signature = TypeDecl.Method(clsType, retType, paramTypes)
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
    private fun parseEnum(): TypeDecl.Enum {
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
    private fun parseRange(): TypeDecl.Range {
        c.consume('r')
        val typeId = c.parseTypeId()
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
    private fun parseComplex(): TypeDecl.Complex {
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
    private fun parseXRef(): TypeDecl.XRef {
        c.consume('x')
        val kindChar = c.advance()
        val kind =
            when (kindChar) {
                's' -> AggrKind.STRUCT
                'u' -> AggrKind.UNION
                'c', 'Y' -> AggrKind.CLASS
                else -> throw StabsParseException(c.pos - 1, c.src, "unknown cross-ref kind '$kindChar'")
            }
        val tagName = c.readUntilAny(charArrayOf(':'))
        c.consume(':')
        return TypeDecl.XRef(kind, tagName)
    }

    /**
     * Parse a size attribute: `@s<n>;<inner>`
     * The `n` is in bits; the inner type is parsed recursively.
     *
     * Mirror of gcc/dbxout.c:dbxout_type (size-attribute emission).
     */
    private fun parseSizeAttr(): TypeDecl.WithSizeAttr {
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
    private fun parseArray(): TypeDecl.Array {
        c.consume('a')
        val indexType = parseType()
        c.consume(';')
        val elementType = parseType()

        // Optional range bounds (not always present)
        val length =
            if (c.peekOrNull() == ';') {
                c.advance()
                val min = c.parseRangeBound()
                c.consume(';')
                val max = c.parseRangeBound()
                c.consume(';')
                max - min + 1
            } else {
                null
            }

        return TypeDecl.Array(elementType, length, indexType)
    }

    /**
     * Parse a function type: `f<return-type>`
     * Note: stabs function descriptors typically don't carry parameter types in the type itself;
     * parameters come via separate `:p`/`:P` records. The Method (#) form DOES carry params.
     *
     * Mirror of gdb/stabsread.c:read_type (f case).
     */
    private fun parseFunctionT(): TypeDecl.FunctionT {
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
    private fun parseMethod(): TypeDecl.Method {
        c.consume('#')
        val clsType = parseType()
        c.consume(',')
        val retType = parseType()
        c.consume(';')

        val params = mutableListOf<TypeDecl>()
        while (!c.startsWith(";")) {
            params.add(parseType())
            c.consumeIf(';')
        }

        c.consume(';')
        return TypeDecl.Method(clsType, retType, params)
    }

    // ===== Helpers =====

    /**
     * Parse an access specifier: 0=private, 1=protected, 2=public.
     */
    private fun parseAccess(ch: Char): Access =
        when (ch) {
            '0' -> Access.PRIVATE
            '1' -> Access.PROTECTED
            '2' -> Access.PUBLIC
            else -> Access.PUBLIC // default
        }

    /**
     * Read a trailing register number (after `:P`, `:r`, etc.).
     * Format: type-info followed by `;` and register number.
     */
    private fun readTrailingReg(): Int {
        // Consume the type descriptor
        parseType()
        c.consume(';')
        val reg = c.parseInt().toInt()
        return reg
    }
}
