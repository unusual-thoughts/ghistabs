package ghistabs.render

import ghidra.program.model.data.ByteDataType
import ghidra.program.model.data.CharDataType
import ghidra.program.model.data.SignedByteDataType
import ghistabs.harvest.GhidraSourceFile
import ghistabs.harvest.StaticSymbol
import ghistabs.harvest.Symbol
import ghistabs.harvest.Type
import ghistabs.index.TypeGraph
import ghistabs.materialize.TemplateNameShortener
import ghistabs.materialize.cpp.abi.Itanium
import ghistabs.materialize.resolveBuiltin
import ghistabs.parse.*

/**
 * Renders one declaration, symbol or type at a time: its text, the spelling of the types in it, and
 * the [Claim] it makes. Everything here works on a single declaration and needs nothing from the
 * file being assembled around it. Implemented by [FileRenderer]; [Region] holds one to spell its
 * decompiled rows the same way.
 */
interface RenderContext {
    val source: GhidraSourceFile
    val renderer: Renderer

    val program get() = renderer.ctx.program
    val resolver get() = renderer.ctx.resolver
    val types get() = renderer.types
    val sourceIndex get() = renderer.sourceIndex
    val shortener: TemplateNameShortener? get() = renderer.shortener

    fun Int?.indentAt(): Int
    fun Int?.isStale(): Boolean

    /** The type alone, as C spells it: an abstract declarator (`int (*)()`). See [spell]. */
    fun GlobalTypeDecl.render(): String = spell("", types, shortener)

    /** True if this resolves to a pointer, seeing through refs, cv-qualifiers and typedefs. */
    fun GlobalTypeDecl.isPointer(types: TypeGraph) = types.resolve<TypeDecl.Pointer<GlobalTypeId>>(this) != null

    /** True if this resolves to an array of char — a string literal — through cv-quals and typedefs. */
    fun GlobalTypeDecl.isCharArray(types: TypeGraph) =
        types.resolve<TypeDecl.Array<GlobalTypeId>>(this)?.element?.isCharType(types) == true

    // Any 1-byte integer element: cygwin's named `char` resolves through its Range body to
    // Byte, not Char. The printable-run guard in stringLiteralAt keeps binary byte[] as hex.
    private fun GlobalTypeDecl.isCharType(types: TypeGraph) = types.resolveAny(this) { decl ->
        decl.resolveBuiltin().let { it is CharDataType || it is ByteDataType || it is SignedByteDataType }
    }

    /** Render a Struct's body members for in-skeleton expansion: one bare C-style decl per entry. */
    fun TypeDecl.Aggregate<GlobalTypeId>.renderFull(owner: String? = null): List<String> {
        val instanceFields = fields.filterNot { it.isStatic }.sortedBy { it.offsetBits }.map { f ->
            f.access to "${f.type.renderDecl(f.name)};  /* +${f.offsetBits / 8}B */"
        }
        // Static members occupy no storage, so they have no offset to sort by and were dropped outright.
        // Their linkage name is the only stabs link to the emitted symbol, so show it.
        val staticFields = fields.filter { it.isStatic }.map { f ->
            f.access to "static ${f.type.renderDecl(f.name)};${f.mangled?.let { "  /* $it */" }.orEmpty()}"
        }
        // gcc emits a stab per aliased copy (ctor C1/C2, dtor D0/D1/D2); once the return type and `this`
        // are gone they render identically, and a class body cannot declare the same member twice.
        val methodDecls = methods.mapNotNull { m ->
            m.mangled?.let { sourceIndex.functionsByMangledName[it] }
                ?.let { program.functionManager.getFunctionAt(it.addr) }
                ?.let {
                    // Ghidra's model carries a return type on every function and `this` as a real
                    // parameter; neither is legal in a class body, where a constructor has no return type
                    // and `this` is a keyword. A member is named for its class exactly when it is one of
                    // the two — [owner] naming the class the bare declaration cannot.
                    val ctor = owner != null && (it.name == owner || it.name == "~$owner")
                    m.access to "${m.declPrefix}${it.prototype(dropThis = true, dropReturnType = ctor)}${m.declSuffix};"
                }
        }.distinct()

        // C++ access sections: emit an `access:` label only when a member deviates from the running
        // access, starting at the type's default (private for a class, public for a struct/union), so a
        // uniform type stays label-free and only real transitions show.
        return buildList {
            var current = if (isCxxClass) Access.PRIVATE else Access.PUBLIC
            for ((access, line) in instanceFields + staticFields + methodDecls) {
                if (access != current) {
                    add("${access.name.lowercase()}:")
                    current = access
                }
                add(line)
            }
        }
    }

    // Only a local carries a role, and only when asked for. A parameter's was noise: it labelled
    // `(param)` a declaration whose own function signature, two columns away, already showed it to
    // be one. A local's storage is real but is a fact about the compiled code rather than the
    // source being reconstructed, so it is opt-in — and spelled by the same [dbxStorageName] the
    // scope plate comments use, so `EBX` and `Stack[-0x38]` mean there exactly what they mean here.
    fun Symbol<*>.renderVar(showStorage: Boolean) = when (body) {
        is SymbolDecl.Local -> body.name to if (showStorage) storage(program) else null
        is SymbolDecl.Param -> body.name to null
        else -> null
    }?.let { (name, role) ->
        Var(
            line,
            name,
            "${body.type.renderDecl(body.name)};",
            role,
        )
    }

    /** A C declaration of [name] with this type — `char (*(*x[3])())[5]`, not type-then-name. */
    fun GlobalTypeDecl.renderDecl(name: String): String = spell(name, types, shortener)

    /** A type body on one line — the appendix form, where alignment to a source line is meaningless. */
    fun Type.oneLineBody(): String = when (val b = body) {
        is TypeDecl.Aggregate -> {
            // Bases too — they are where the instantiations differ most visibly, and dropping them
            // was the one thing the appendix still lost against the pre-rewrite render.
            val bases = b.spellBases(types, shortener)
            ("${b.cxxKeyword} ${shortener?.shortenedOrNull(name ?: "") ?: name}$bases { ")
                .asSpecialization(shortener?.shortenedOrNull(name ?: "") ?: name) +
                b.renderFull(name?.simpleTypeName()).joinToString(" ") +
                " }; /* ${b.sizeBytes} bytes */"
        }

        is TypeDecl.Enum ->
            "enum $name { ${b.members.joinToString(", ") { (n, v) -> "$n = $v" }} }; /* ${b.members.size} members */"

        else -> "$name;"
    }

    fun Type.emitTypeBody(instantiations: Int): Claim? {
        if (name == null) {
            return null
        }

        val name = name ?: return null
        val shortName = shortener?.shortenedOrNull(name) ?: name

        // Struct fields/methods are self-terminated statements; enum members carry a
        // trailing comma so the space-join in layoutBraceBlock reads as a member list.
        val members = when (body) {
            is TypeDecl.Aggregate -> body.renderFull(name.simpleTypeName())
            is TypeDecl.Enum -> body.members.map { (mn, mv) -> "$mn = $mv," }
            else -> return null
        }
        // `:t` bound the name, so the source wrote `typedef struct {…} Name;` — render that form,
        // with the name after the closing brace rather than after the keyword.
        val isTypedef = kind == TypeNameKind.TYPEDEF
        val tag = if (isTypedef) "typedef " else ""
        val declName = if (isTypedef) "" else " $shortName"
        val openText = when (body) {
            is TypeDecl.Aggregate -> body.spellBases(types, shortener).let { bases ->
                "$tag${body.cxxKeyword}$declName$bases {".asSpecialization(shortName)
            }

            is TypeDecl.Enum -> tag + "enum$declName {"
        }
        val extent = when (body) {
            is TypeDecl.Aggregate -> "${body.sizeBytes} bytes"
            is TypeDecl.Enum -> "${body.members.size} members"
        }
        val sizeNote = "/* $extent" + (if (instantiations > 1) ", $instantiations instantiations" else "") + " */"
        val stale = line.isStale()
        return if (members.isNotEmpty()) {
            Claim(
                Owner.TYPE_BODY,
                line,
                FileRenderer.braceRows(
                    openText,
                    members,
                    (if (isTypedef) "} $shortName; " else "}; ") + sizeNote,
                    line.indentAt(),
                    "",
                ),
                Fit.ELASTIC,
                stale,
            )
        } else {
            // No members to wrap, so there is nothing to typedef *around*: the bare tag form is the
            // only spelling that parses.
            val keyword = if (body is TypeDecl.Aggregate) body.cxxKeyword else "enum"
            val row = Row("$keyword $shortName; $sizeNote", line.indentAt(), "")
            Claim(Owner.TYPE_BODY, line, listOf(row), stale = stale)
        }
    }

    // A global/static: the linker's data at [addr] renders as its initializer — a scalar
    // inline, a multi-element aggregate spread over the blank lines below (the same
    // brace-block layout as a struct body).
    fun StaticSymbol.emitGlobal(): Claim {
        val scope = body.scope.comment()
        val role = when (recordType) {
            StabType.N_GSYM if body.scope == StaticScope.GLOBAL -> "(global)"
            StabType.N_GSYM -> "(weird global $scope)"
            StabType.N_LCSYM -> "(.bss $scope)"
            StabType.N_STSYM -> "(.data $scope)"
            StabType.N_ROSYM -> "(.rodata $scope)"
            else -> "($scope)"
        }
        // N_GSYM has rawValue=0 (linker resolves it from the mangled name) — look it up.
        val addr = resolver.forSymbol(this)

        // Without -gstabs+ there is no decl line: the claim is band-anchored (Claim.anchoring), so
        // there is no row to indent against and nothing for staleness to be judged past.
        val indent = line.indentAt()
        val base = body.type.renderDecl(renderer.staticMemberNames[body.name] ?: body.name)
        // A string-valued global (pointer-to-string whose slot Ghidra left an untyped
        // scalar, or a char[N] holding an RTTI/string literal) renders as one quoted
        // literal; initializerAt would otherwise miss it or spread a per-byte list.
        val literal = addr?.let {
            when {
                body.type.isPointer(types) -> program.pointerString(it)
                body.type.isCharArray(types) -> program.stringLiteralAt(it)
                else -> null
            }
        }
        val parts = literal?.let { listOf(it) } ?: addr?.let { program.initializerAt(it) }
        // Judged for misattribution like any other declaration. gcc drops the file of every deferred
        // file-scope static (`dbxout_prepare_symbol` emits the symbol's own N_SOL only under
        // WINNING_GDB), so these are the *most* likely records to be filed under the wrong source —
        // twenty `vmN_trapset_names` tables from a header gcc filed into main.cpp, reaching L1342 in a
        // file whose code stops at L166. See §38.
        val stale = line.isStale()
        val owner = if (Itanium.isGeneratedData(body.name)) Owner.GENERATED else Owner.GLOBAL
        return when {
            parts == null -> Claim(owner, line, listOf(Row("$base;", indent, role)), stale = stale)

            parts.size == 1 -> Claim(
                owner,
                line,
                listOf(Row("$base = ${parts[0]};", indent, role)),
                stale = stale,
            )

            // A multi-element aggregate knows where it starts and not where it ends.
            else -> Claim(
                owner,
                line,
                FileRenderer.braceRows("$base = {", parts.map { "$it," }, "};", indent, role),
                Fit.ELASTIC,
                stale,
            )
        }
    }
}
