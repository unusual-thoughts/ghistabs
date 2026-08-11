package ghistabs.render

import ghidra.program.model.data.ByteDataType
import ghidra.program.model.data.CharDataType
import ghidra.program.model.data.SignedByteDataType
import ghidra.program.model.listing.Program
import ghistabs.harvest.HarvestIndex
import ghistabs.harvest.Symbol
import ghistabs.materialize.TemplateNameShortener
import ghistabs.materialize.resolveBuiltin
import ghistabs.parse.Access
import ghistabs.parse.AggrKind
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.SymbolDecl
import ghistabs.parse.TypeDecl

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
fun TypeDecl<GlobalTypeId>.render(
    index: HarvestIndex,
    seen: Set<GlobalTypeId> = emptySet(),
    shortener: TemplateNameShortener? = null,
): String = when (this) {
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
            else -> ast.body.render(index, seen + id, shortener)
        }
    }

    is TypeDecl.Pointer -> "${inner.render(index, seen, shortener)} *"

    is TypeDecl.Reference -> "${inner.render(index, seen, shortener)} &"

    is TypeDecl.Const -> "${inner.render(index, seen, shortener)} const"

    is TypeDecl.Volatile -> "${inner.render(index, seen, shortener)} volatile"

    is TypeDecl.Array -> {
        // gcc stores the bound in indexType (`ar<idx>;lo;hi`), leaving length null;
        // derive count as hi-lo+1, same as TypeRegistry's array materialization.
        val len = length ?: (indexType as? TypeDecl.Range)?.let { it.max - it.min + 1 }
        "${element.render(index, seen, shortener)}[${len ?: ""}]"
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
        val ret = ret.render(index, seen, shortener)
        val params = params.joinToString(", ") { it.render(index, seen, shortener) }
        "$ret($params)"
    }

    is TypeDecl.Method -> {
        val cls = cls.render(index, seen, shortener)
        val ret = ret.render(index, seen, shortener)
        val params = params.joinToString(", ") { it.render(index, seen, shortener) }
        "$ret($cls::*)($params)"
    }

    is TypeDecl.InlineDef -> inner.render(index, seen + id, shortener)
}

/**
 * Shortener seeded from the stabs typedefs themselves (typedef name → aliased type's name), for the
 * skeleton renderer, which spells types from the harvest AST rather than the DTM (so the DTM
 * shortening pass doesn't reach it). Only typedefs whose target is a template instantiation (has a
 * `<`) are used — that excludes base-type aliases (`fpos_t`→`longlong`) without DataType lookups.
 */
fun harvestTemplateShortener(index: HarvestIndex): TemplateNameShortener {
    fun targetName(decl: TypeDecl<GlobalTypeId>): String? = when (decl) {
        is TypeDecl.Ref -> index.byId(decl.id)?.name
        is TypeDecl.XRef -> decl.tagName
        is TypeDecl.InlineDef -> targetName(decl.inner)
        else -> null
    }
    val aliases = index.allTypes.mapNotNull { ast ->
        val name = ast.name ?: return@mapNotNull null
        targetName(ast.body)?.takeIf { '<' in it && it.length > name.length }?.let { name to it }
    }.toMap()
    return TemplateNameShortener(aliases)
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
fun TypeDecl.Struct<GlobalTypeId>.renderFull(
    index: HarvestIndex,
    program: Program,
    shortener: TemplateNameShortener? = null,
    owner: String? = null,
): List<String> {
    val members = fields.filter { !it.isStatic }.sortedBy { it.offsetBits }.map { f ->
        f.access to "${f.type.renderDecl(f.name, index, shortener)};  /* +${f.offsetBits / 8}B */"
    } + fields.filter { it.isStatic }.map { f ->
        // Static members occupy no storage, so they have no offset to sort by and were dropped
        // outright. Their linkage name is the only stabs link to the emitted symbol, so show it.
        val link = f.mangled?.let { "  /* $it */" }.orEmpty()
        f.access to "static ${f.type.renderDecl(f.name, index, shortener)};$link"
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

/** One stabs variable of a function, declared in this file: where gcc put it and how it renders. */
data class Var(val line: Int, val name: String, val text: String, val role: String?)

// Only a local carries a role, and only when asked for. A parameter's was noise: it labelled
// `(param)` a declaration whose own function signature, two columns away, already showed it to
// be one. A local's storage is real but is a fact about the compiled code rather than the
// source being reconstructed, so it is opt-in — and spelled by the same [dbxStorageName] the
// scope plate comments use, so `EBX` and `Stack[-0x38]` mean there exactly what they mean here.
fun Symbol.renderVar(index: HarvestIndex, program: Program, shortener: TemplateNameShortener, showStorage: Boolean) =
    when (body) {
        is SymbolDecl.Local -> body.name to if (showStorage) storage(program) else null
        is SymbolDecl.Param -> body.name to null
        else -> null
    }?.let { (name, role) ->
        Var(
            declLine,
            name,
            "${body.type.renderDecl(body.name, index, shortener)};",
            role,
        )
    }

/**
 * A C declaration of [name] with this type. C is declarator-based: an array's extent goes *after* the
 * name, so `char const[18] _ZTS7XVImage` — which is what type-then-name produces, and what clang
 * rejects with "brackets are not allowed here" — has to be `char const _ZTS7XVImage[18]`.
 */
fun TypeDecl<GlobalTypeId>.renderDecl(
    name: String,
    index: HarvestIndex,
    shortener: TemplateNameShortener? = null,
): String = declarator(render(index, shortener = shortener), name)

private val ARRAY_SUFFIX = Regex("""((?:\[[^\]]*\])+)$""")

internal fun declarator(type: String, name: String) = ARRAY_SUFFIX.find(type)
    ?.let { "${type.removeSuffix(it.value).trimEnd()} $name${it.value}" }
    ?: "$type $name"
