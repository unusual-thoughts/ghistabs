package ghistabs.parse

/**
 * Recursive-descent parser for stabs type/symbol descriptors as emitted by Cygwin gcc 3.4.4.
 *
 * Trailing input after a complete symbol is silently ignored — callers handle multi-record splitting.
 */
class Parser(src: String) {
    private val c = Cursor(src)

    /** Parse `name:descriptor` — mirror of `gdb/stabsread.c:define_symbol`. */
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

    /** Parse a bare type descriptor body. Exposed for tests. */
    fun parseTypeBody(): TypeDecl<LocalTypeId> = parseType()

    // ===== Symbol-level productions =====

    /** `:T(cu,n)[=body]` — body-less form is a forward decl resolved by a later stab. */
    private fun parseTagged(name: String): SymbolDecl.TaggedType<LocalTypeId> {
        c.consume('T')
        c.consumeIf('t') // gcc emits Tt for combined tagged+typedef (`typedef struct foo {} foo`)
        val id = c.parseTypeId()
        val body = if (c.consumeIf('=')) parseType() else TypeDecl.Ref(id)
        return SymbolDecl.TaggedType(name, id, body)
    }

    /** `:t(cu,n)[=body]` — body-less typedef forward decl is common with cygwin gcc 13+ on C++23 code. */
    private fun parseTypedef(name: String): SymbolDecl.Typedef<LocalTypeId> {
        c.consume('t')
        val id = c.parseTypeId()
        val body = if (c.consumeIf('=')) parseType() else TypeDecl.Ref(id)
        return SymbolDecl.Typedef(name, id, body)
    }

    // ===== Type descriptor dispatch =====

    /** Mirror of `gdb/stabsread.c:read_type`. */
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
            // Forward ref, inline def, or builtin slot: (cu,n) / bare n, optionally followed by `=`.
            val id = c.parseTypeId()
            when {
                c.consumeIf('=') -> TypeDecl.InlineDef(id, parseType())

                // Negative type number = gcc XCOFF builtin slot. Per stabs spec: no defining stab
                // ever follows, so bind directly to Builtin rather than leaving a dangling Ref.
                id.file == 0 && id.n < 0 -> TypeDecl.Builtin(id.n)

                else -> TypeDecl.Ref(id)
            }
        }

        else -> throw StabsParseException(c.pos, c.src, "unexpected character '$ch' in type descriptor")
    }

    // ===== Type productions =====

    /**
     * Parse a struct/union/class body: `<size>[!<inheritance>][~%<vtable-id>;]<members>;;`.
     * Mirror of `gdb/stabsread.c:read_struct_type`.
     */
    private fun parseStruct(kind: AggrKind): TypeDecl.Struct<LocalTypeId> {
        val sizeBytes = c.parseInt()

        val bases = if (c.consumeIf('!')) {
            parseInheritanceList()
        } else {
            emptyList()
        }

        val (hasVTablePointer, vtableTypeId) = if (c.consumeIf('~')) {
            c.consume('%')
            val id = c.parseTypeId()
            c.consume(';')
            Pair(true, id)
        } else {
            Pair(false, null)
        }

        // Member list: each field/method ends in `;`, the list itself ends in a bare `;`,
        // so the struct closes with `;;`. Loop exits when peek sees the second `;`.
        val fields = mutableListOf<FieldDecl<LocalTypeId>>()
        val methods = mutableListOf<MethodDecl<LocalTypeId>>()

        while (c.peekOrNull() != ';' && !c.eof) {
            val name = c.readUntilAny(charArrayOf(':', '/'))

            when {
                c.startsWith("::") -> {
                    // Method: `name::<overload1>[<overload2>...];` — gcc concatenates overloads
                    // with no separator; loop until the next char is not the start of a TypeId.
                    c.advance()
                    c.advance()
                    methods.add(parseMethodBlock(name))
                    while (c.peekOrNull().let { it == '(' || (it != null && it.isDigit()) }) {
                        methods.add(parseMethodBlock(name))
                    }
                }

                c.startsWith(":/") -> {
                    // `name:/<access><type>{,<offset>,<size>|:<mangled>};`
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
                        c.readUntilAny(charArrayOf(';')) // mangled symbol — discarded; comes from COFF symtab
                        c.consume(';')
                        fields.add(FieldDecl(name, type, 0, 0, isStatic = true))
                    }
                }

                c.startsWith(":") -> {
                    // `name:<type>,<offset>,<size>;`
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
                    // Static field, access-prefixed form (no leading `:`).
                    c.advance()
                    val access = parseAccess(if (!c.eof) c.advance() else '2')
                    val type = parseType()
                    c.consume(':')
                    c.readUntilAny(charArrayOf(';')) // mangled symbol — discarded; comes from COFF symtab
                    c.consume(';')
                    fields.add(FieldDecl(name, type, 0, 0, isStatic = true))
                }

                else -> {
                    throw StabsParseException(c.pos, c.src, "unexpected character in struct field")
                }
            }
        }

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
     * `!<count>,<base>;...` where each base is `<virt><access><offset>,<base-id>;`.
     * Mirror of `gdb/stabsread.c:read_cpp_abbrev`.
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
            val baseType = parseType()
            c.consume(';')
            bases.add(BaseDecl(baseType, virt, access, offsetBits))
        }

        return bases
    }

    /**
     * One method overload following `::`:
     * `(cu,n)[=#cls,ret,p1,...;]:mangled;<access><modifier><virt>[*<voff>;<vthistype>;]`.
     * Mirror of `gdb/stabsread.c:read_member_functions`.
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
                parseType() // vthistype — consumed, not stored
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

    /** `e<name>:<value>,...;` — mirror of `gdb/stabsread.c:read_enum_type`. */
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
     * `r<id>;<min>;<max>;` — mirror of `gdb/stabsread.c:read_range_type`.
     *
     * Returns [TypeDecl.Float] for the gcc float encoding `r<base>;<NBYTES>;0;` (min>0 && max==0);
     * `<base>` is decorative per spec.
     */
    private fun parseRange(): TypeDecl<LocalTypeId> {
        c.consume('r')
        val typeId = c.parseTypeId()
        // gcc may define the base inline: `r(cu,n)=<inner>;lo;hi;`.
        if (c.consumeIf('=')) {
            parseType()
        }
        c.consume(';')
        val min = c.parseRangeBound()
        c.consume(';')
        val max = c.parseRangeBound()
        c.consume(';')
        if (max == 0L && min > 0L) {
            return TypeDecl.Float(min.toInt())
        }
        return TypeDecl.Range(typeId, min, max)
    }

    /**
     * `R<n>;<size>;0;` — n encodes type (3=cfloat, 4=cdouble, 5=cldouble per gcc/dbxout.c).
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
     * `x<kind><name>:` where kind ∈ {s,u,e,c,Y} (Y is the gcc-2 class form).
     * Mirror of `gdb/stabsread.c:read_cross_ref` / stabs.html §4.6.
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
        val tagName = c.readXRefTagName() // skips `::` inside `<>`, stops at single `:` at depth 0
        c.consume(':')
        return TypeDecl.XRef(kind, tagName)
    }

    /** `@s<bits>;<inner>` — bit-width override per stabs.texinfo §"String Field". */
    private fun parseSizeAttr(): TypeDecl.WithSizeAttr<LocalTypeId> {
        c.consume('@')
        c.consume('s')
        val sizeBits = c.parseInt().toInt()
        c.consume(';')
        val inner = parseType()
        return TypeDecl.WithSizeAttr(sizeBits, inner)
    }

    /** `a<index-type><element-type>` — no separator; parseRange consumes its own trailing `;`. */
    private fun parseArray(): TypeDecl.Array<LocalTypeId> {
        c.consume('a')
        val indexType = parseType()
        val elementType = parseType()
        return TypeDecl.Array(elementType, null, indexType)
    }

    /**
     * `f<return-type>` — stabs `f` descriptors carry no parameter types
     * (those come via separate `:p`/`:P` records). The `#` form does carry params.
     */
    private fun parseFunctionT(): TypeDecl.FunctionT<LocalTypeId> {
        c.consume('f')
        val retType = parseType()
        return TypeDecl.FunctionT(retType, emptyList())
    }

    /** `#<cls>,<ret>;<params>;` — pointer-to-member-function, params inline. */
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

    /** 0=private, 1=protected, 2=public; unknown → public. */
    private fun parseAccess(ch: Char): Access = when (ch) {
        '0' -> Access.PRIVATE
        '1' -> Access.PROTECTED
        '2' -> Access.PUBLIC
        else -> Access.PUBLIC
    }

    /** Register number lives in `n_value`, not the descriptor string. */
    private fun readTrailingReg(): Int = 0
}
