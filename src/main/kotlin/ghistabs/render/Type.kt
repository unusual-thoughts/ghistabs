package ghistabs.render

import ghidra.program.model.data.ByteDataType
import ghidra.program.model.data.CharDataType
import ghidra.program.model.data.SignedByteDataType
import ghidra.program.model.listing.Program
import ghistabs.harvest.*
import ghistabs.importer.AddressResolver
import ghistabs.materialize.TemplateNameShortener
import ghistabs.materialize.itanium.Itanium
import ghistabs.materialize.resolveBuiltin
import ghistabs.parse.*
import ghistabs.scan.Definition

/** One stabs variable of a function, declared in this file: where gcc put it and how it renders. */
data class Var(val line: Int?, val name: String, val text: String, val role: String?)

interface RenderContext {
    val source: GhidraSourceFile
    val program: Program
    val resolver: AddressResolver
    val index: HarvestIndex
    val shortener: TemplateNameShortener?

    fun indentFor(line: Int?): Int
    fun isStale(line: Int?): Boolean

    /** The definition a line sits in, read off the real source `--source-root` mapped. */
    fun enclosing(source: GhidraSourceFile, line: Int): Definition?

    /**
     * Best-effort C-style rendering of a [TypeDecl]. Primitives go
     * through [resolveBuiltin] so they come out as `int` / `uchar` /
     * `double` etc; named composite types are looked up by id in
     * the index. Cycles (gcc's recursive
     * `std::basic_string<…>::operator=` taking `std::string&`) are broken
     * with a visited-set of the type ids on the current path — NOT a depth
     * cap, which the transparent Ref/InlineDef indirections would exhaust
     * on legitimately deep types (e.g. an array of const char pointers:
     * Array→InlineDef→Const→Ref→Pointer→Ref→Const→Ref→char).
     */
    fun TypeDecl<GlobalTypeId>.render(seen: Set<GlobalTypeId> = emptySet()): String = when (this) {
        TypeDecl.Void -> "void"

        is TypeDecl.Ref -> {
            // Named TypeAst → use the name. Anonymous → recurse into its body so the
            // user sees `int *` rather than a raw GlobalTypeId, unless this id is
            // already on the path (cycle). Unresolved (cross-CU dangling) → id string.
            val ast = index.byId(id)
            val name = ast?.name
            when {
                name != null -> shortener?.shortenedOrNull(name) ?: name
                ast == null -> "T_$id"
                id in seen -> "…"
                else -> ast.body.render(seen + id)
            }
        }

        is TypeDecl.Pointer -> "${inner.render(seen)} *"

        is TypeDecl.Reference -> "${inner.render(seen)} &"

        is TypeDecl.Const -> "${inner.render(seen)} const"

        is TypeDecl.Volatile -> "${inner.render(seen)} volatile"

        is TypeDecl.Array -> {
            // gcc stores the bound in indexType (`ar<idx>;lo;hi`), leaving length null;
            // derive count as hi-lo+1, same as TypeRegistry's array materialization.
            val len = length ?: (indexType as? TypeDecl.Range)?.let { it.max - it.min + 1 }
            "${element.render(seen)}[${len ?: ""}]"
        }

        is TypeDecl.Builtin,
        is TypeDecl.Range,
        is TypeDecl.Float,
        is TypeDecl.Complex,
        is TypeDecl.WithSizeAttr,
        -> resolveBuiltin()?.name ?: this::class.simpleName?.lowercase() ?: "?"

        is TypeDecl.XRef -> "${kind.cxxKeyword()} ${shortener?.shortenedOrNull(tagName) ?: tagName}"

        is TypeDecl.Struct -> kind.cxxKeyword()

        is TypeDecl.Enum -> "enum"

        is TypeDecl.FunctionT -> {
            val ret = ret.render(seen)
            val params = params.joinToString(", ") { it.render(seen) }
            "$ret($params)"
        }

        is TypeDecl.Method -> {
            val cls = cls.render(seen)
            val ret = ret.render(seen)
            val params = params.joinToString(", ") { it.render(seen) }
            "$ret($cls::*)($params)"
        }

        is TypeDecl.InlineDef -> inner.render(seen + id)
    }

    /** True if this resolves to a pointer, seeing through refs, cv-qualifiers and typedefs. */
    fun TypeDecl<GlobalTypeId>.isPointer(index: HarvestIndex): Boolean = when (this) {
        is TypeDecl.Pointer -> true
        is TypeDecl.Const -> inner.isPointer(index)
        is TypeDecl.Volatile -> inner.isPointer(index)
        is TypeDecl.InlineDef -> inner.isPointer(index)
        is TypeDecl.Ref -> index.byId(id)?.body?.isPointer(index) ?: false
        else -> false
    }

    /** True if this resolves to an array of char — a string literal — through cv-quals and typedefs. */
    fun TypeDecl<GlobalTypeId>.isCharArray(index: HarvestIndex): Boolean = when (this) {
        is TypeDecl.Array -> element.isCharType(index)
        is TypeDecl.Const -> inner.isCharArray(index)
        is TypeDecl.Volatile -> inner.isCharArray(index)
        is TypeDecl.InlineDef -> inner.isCharArray(index)
        is TypeDecl.Ref -> index.byId(id)?.body?.isCharArray(index) ?: false
        else -> false
    }

    private fun TypeDecl<GlobalTypeId>.isCharType(index: HarvestIndex): Boolean = when (this) {
        is TypeDecl.Const -> inner.isCharType(index)

        is TypeDecl.Volatile -> inner.isCharType(index)

        is TypeDecl.InlineDef -> inner.isCharType(index)

        is TypeDecl.Ref -> index.byId(id)?.body?.isCharType(index) ?: false

        // Any 1-byte integer element: cygwin's named `char` resolves through its Range body to
        // Byte, not Char. The printable-run guard in stringLiteralAt keeps binary byte[] as hex.
        else -> when (resolveBuiltin()) {
            is CharDataType, is ByteDataType, is SignedByteDataType -> true
            else -> false
        }
    }

    /** Render a Struct's body members for in-skeleton expansion: one bare C-style decl per entry. */
    fun TypeDecl.Struct<GlobalTypeId>.renderFull(owner: String? = null): List<String> {
        val members = fields.filter { !it.isStatic }.sortedBy { it.offsetBits }.map { f ->
            f.access to "${f.type.renderDecl(f.name)};  /* +${f.offsetBits / 8}B */"
        } + fields.filter { it.isStatic }.map { f ->
            // Static members occupy no storage, so they have no offset to sort by and were dropped
            // outright. Their linkage name is the only stabs link to the emitted symbol, so show it.
            val link = f.mangled?.let { "  /* $it */" }.orEmpty()
            f.access to "static ${f.type.renderDecl(f.name)};$link"
        } + methods.mapNotNull { m ->
            m.mangled?.let { index.functionsByMangledName[it] }
                ?.let { program.functionManager.getFunctionAt(it.addr) }
                ?.let {
                    // Ghidra's model carries a return type on every function and `this` as a real
                    // parameter; neither is legal in a class body, where a constructor has no return type
                    // and `this` is a keyword. A member is named for its class exactly when it is one of
                    // the two — [owner] naming the class the bare declaration cannot.
                    val ctor = owner != null && (it.name == owner || it.name == "~$owner")
                    m.access to "${m.declPrefix}${it.prototype(dropThis = true, dropReturnType = ctor)}${m.declSuffix};"
                }
            // gcc emits a stab per aliased copy (ctor C1/C2, dtor D0/D1/D2); once the return type and
            // `this` are gone they render identically, and a class body cannot declare the same member
            // twice.
        }.distinct()

        // C++ access sections: emit an `access:` label only when a member deviates from the running
        // access, starting at the type's default (private for a class, public for a struct/union), so a
        // uniform type stays label-free and only real transitions show.
        return buildList {
            var current = if (kind == AggrKind.CLASS) Access.PRIVATE else Access.PUBLIC
            for ((access, line) in members) {
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
            declLine,
            name,
            "${body.type.renderDecl(body.name)};",
            role,
        )
    }

    /**
     * A C declaration of [name] with this type. C is declarator-based: an array's extent goes *after* the
     * name, so `char const[18] _ZTS7XVImage` — which is what type-then-name produces, and what clang
     * rejects with "brackets are not allowed here" — has to be `char const _ZTS7XVImage[18]`.
     */
    fun TypeDecl<GlobalTypeId>.renderDecl(name: String): String = declarator(render(), name)

    /** A type body on one line — the appendix form, where alignment to a source line is meaningless. */
    fun Type.oneLineBody(): String = when (val b = body) {
        is TypeDecl.Struct -> {
            // Bases too — they are where the instantiations differ most visibly, and dropping them
            // was the one thing the appendix still lost against the pre-rewrite render.
            val bases = b.bases.takeIf { it.isNotEmpty() }
                ?.joinToString(", ", prefix = " : ") {
                    "${it.access.name.lowercase()} ${it.type.render()}"
                }
                .orEmpty()
            ("${b.kind.cxxKeyword()} ${shortener?.shortenedOrNull(name ?: "") ?: name}$bases { ")
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

        val shortName = shortener?.shortenedOrNull(name) ?: name

        // Struct fields/methods are self-terminated statements; enum members carry a
        // trailing comma so the space-join in layoutBraceBlock reads as a member list.
        val members = when (body) {
            is TypeDecl.Struct -> body.renderFull(name.simpleTypeName())
            is TypeDecl.Enum -> body.members.map { (mn, mv) -> "$mn = $mv," }
            else -> return null
        }
        val openText = when (body) {
            is TypeDecl.Struct -> body.bases.takeIf { it.isNotEmpty() }?.joinToString(", ", prefix = " : ") {
                "${it.access.name.lowercase()} ${it.type.render()}"
            }.orEmpty().let { bases ->
                "${body.kind.cxxKeyword()} $shortName$bases {".asSpecialization(shortName)
            }

            is TypeDecl.Enum -> "enum $shortName {"
        }
        val extent = when (body) {
            is TypeDecl.Struct -> "${body.sizeBytes} bytes"
            is TypeDecl.Enum -> "${body.members.size} members"
        }
        val sizeNote = "/* $extent" + (if (instantiations > 1) ", $instantiations instantiations" else "") + " */"
        val stale = isStale(declLine)
        return if (members.isNotEmpty()) {
            Claim(
                Owner.TYPE_BODY,
                declLine,
                FileRenderer.braceRows(openText, members, "}; $sizeNote", indentFor(declLine), ""),
                Fit.ELASTIC,
                stale,
            )
        } else {
            val keyword = if (body is TypeDecl.Struct) body.kind.cxxKeyword() else "enum"
            val row = Row("$keyword $shortName; $sizeNote", indentFor(declLine), "")
            Claim(Owner.TYPE_BODY, declLine, listOf(row), stale = stale)
        }
    }

    // A global/static: the linker's data at [addr] renders as its initializer — a scalar
    // inline, a multi-element aggregate spread over the blank lines below (the same
    // brace-block layout as a struct body).
    fun emitGlobal(rec: StaticSymbol): Claim {
        val sym = rec.body
        val scope = sym.scope.comment()
        val role = when (rec.recordType) {
            StabType.N_GSYM if sym.scope == StaticScope.GLOBAL -> "(global)"
            StabType.N_GSYM -> "(weird global $scope)"
            StabType.N_LCSYM -> "(.bss $scope)"
            StabType.N_STSYM -> "(.data $scope)"
            StabType.N_ROSYM -> "(.rodata $scope)"
            else -> "($scope)"
        }
        // N_GSYM has rawValue=0 (linker resolves it from the mangled name) — look it up.
        val addr = resolver.forSymbol(rec)

        // Without -gstabs+ there is no decl line: the claim is band-anchored (Claim.anchoring), so
        // there is no row to indent against and nothing for staleness to be judged past.
        val indent = indentFor(rec.declLine)
        val base = sym.type.renderDecl(sym.name)
        // A string-valued global (pointer-to-string whose slot Ghidra left an untyped
        // scalar, or a char[N] holding an RTTI/string literal) renders as one quoted
        // literal; initializerAt would otherwise miss it or spread a per-byte list.
        val literal = addr?.let {
            when {
                sym.type.isPointer(index) -> program.pointerString(it)
                sym.type.isCharArray(index) -> program.stringLiteralAt(it)
                else -> null
            }
        }
        val parts = literal?.let { listOf(it) } ?: addr?.let { program.initializerAt(it) }
        // Judged for misattribution like any other declaration. gcc drops the file of every deferred
        // file-scope static (`dbxout_prepare_symbol` emits the symbol's own N_SOL only under
        // WINNING_GDB), so these are the *most* likely records to be filed under the wrong source —
        // twenty `vmN_trapset_names` tables from a header gcc filed into main.cpp, reaching L1342 in a
        // file whose code stops at L166. See §38.
        val stale = isStale(rec.declLine)
        val owner = if (Itanium.isGeneratedData(sym.name)) Owner.GENERATED else Owner.GLOBAL
        return when {
            parts == null -> Claim(owner, rec.declLine, listOf(Row("$base;", indent, role)), stale = stale)

            parts.size == 1 -> Claim(
                owner,
                rec.declLine,
                listOf(Row("$base = ${parts[0]};", indent, role)),
                stale = stale,
            )

            // A multi-element aggregate knows where it starts and not where it ends.
            else -> Claim(
                owner,
                rec.declLine,
                FileRenderer.braceRows("$base = {", parts.map { "$it," }, "};", indent, role),
                Fit.ELASTIC,
                stale,
            )
        }
    }
}
