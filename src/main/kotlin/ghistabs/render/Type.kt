package ghistabs.render

import ghidra.program.model.data.ByteDataType
import ghidra.program.model.data.CharDataType
import ghidra.program.model.data.SignedByteDataType
import ghidra.program.model.listing.Program
import ghistabs.harvest.Harvest
import ghistabs.materialize.TemplateNameShortener
import ghistabs.materialize.resolveBuiltin
import ghistabs.parse.Access
import ghistabs.parse.AggrKind
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl

/**
 * Best-effort C-style rendering of a [TypeDecl]. Primitives go
 * through [resolveBuiltin] so they come out as `int` / `uchar` /
 * `double` etc; named composite types are looked up by id in
 * [Harvest.typeAsts]. Cycles (gcc's recursive
 * `std::basic_string<…>::operator=` taking `std::string&`) are broken
 * with a visited-set of the type ids on the current path — NOT a depth
 * cap, which the transparent Ref/InlineDef indirections would exhaust
 * on legitimately deep types (e.g. an array of const char pointers:
 * Array→InlineDef→Const→Ref→Pointer→Ref→Const→Ref→char).
 */
fun TypeDecl<GlobalTypeId>.render(
    harvest: Harvest,
    seen: Set<GlobalTypeId> = emptySet(),
    shortener: TemplateNameShortener? = null,
): String = when (this) {
    is TypeDecl.Ref -> {
        // Named TypeAst → use the name. Anonymous → recurse into its body so the
        // user sees `int *` rather than a raw GlobalTypeId, unless this id is
        // already on the path (cycle). Unresolved (cross-CU dangling) → id string.
        val ast = harvest.typeAsts[id]
        val name = ast?.name
        when {
            name != null -> shortener?.shortenedOrNull(name) ?: name
            ast == null -> "T_$id"
            id in seen -> "…"
            else -> ast.body.render(harvest, seen + id, shortener)
        }
    }

    is TypeDecl.Pointer -> "${pointee.render(harvest, seen, shortener)} *"

    is TypeDecl.Reference -> "${referent.render(harvest, seen, shortener)} &"

    is TypeDecl.Const -> "${inner.render(harvest, seen, shortener)} const"

    is TypeDecl.Volatile -> "${inner.render(harvest, seen, shortener)} volatile"

    is TypeDecl.Array -> {
        // gcc stores the bound in indexType (`ar<idx>;lo;hi`), leaving length null;
        // derive count as hi-lo+1, same as TypeRegistry's array materialization.
        val len = length ?: (indexType as? TypeDecl.Range)?.let { it.max - it.min + 1 }
        "${element.render(harvest, seen, shortener)}[${len ?: ""}]"
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
        val ret = ret.render(harvest, seen, shortener)
        val params = params.joinToString(", ") { it.render(harvest, seen, shortener) }
        "$ret($params)"
    }

    is TypeDecl.Method -> {
        val cls = cls.render(harvest, seen, shortener)
        val ret = ret.render(harvest, seen, shortener)
        val params = params.joinToString(", ") { it.render(harvest, seen, shortener) }
        "$ret($cls::*)($params)"
    }

    is TypeDecl.InlineDef -> body.render(harvest, seen + id, shortener)
}

/**
 * Shortener seeded from the stabs typedefs themselves (typedef name → aliased type's name), for the
 * skeleton renderer, which spells types from the harvest AST rather than the DTM (so the DTM
 * shortening pass doesn't reach it). Only typedefs whose target is a template instantiation (has a
 * `<`) are used — that excludes base-type aliases (`fpos_t`→`longlong`) without DataType lookups.
 */
fun harvestTemplateShortener(harvest: Harvest): TemplateNameShortener {
    fun targetName(decl: TypeDecl<GlobalTypeId>): String? = when (decl) {
        is TypeDecl.Ref -> harvest.typeAsts[decl.id]?.name
        is TypeDecl.XRef -> decl.tagName
        is TypeDecl.InlineDef -> targetName(decl.body)
        else -> null
    }
    val aliases = harvest.typeAsts.values.mapNotNull { ast ->
        val name = ast.name ?: return@mapNotNull null
        targetName(ast.body)?.takeIf { '<' in it && it.length > name.length }?.let { name to it }
    }.toMap()
    return TemplateNameShortener(aliases)
}

/** True if this resolves to a pointer, seeing through refs, cv-qualifiers and typedefs. */
fun TypeDecl<GlobalTypeId>.isPointer(harvest: Harvest): Boolean = when (this) {
    is TypeDecl.Pointer -> true
    is TypeDecl.Const -> inner.isPointer(harvest)
    is TypeDecl.Volatile -> inner.isPointer(harvest)
    is TypeDecl.InlineDef -> body.isPointer(harvest)
    is TypeDecl.Ref -> harvest.typeAsts[id]?.body?.isPointer(harvest) ?: false
    else -> false
}

/** True if this resolves to an array of char — a string literal — through cv-quals and typedefs. */
fun TypeDecl<GlobalTypeId>.isCharArray(harvest: Harvest): Boolean = when (this) {
    is TypeDecl.Array -> element.isCharType(harvest)
    is TypeDecl.Const -> inner.isCharArray(harvest)
    is TypeDecl.Volatile -> inner.isCharArray(harvest)
    is TypeDecl.InlineDef -> body.isCharArray(harvest)
    is TypeDecl.Ref -> harvest.typeAsts[id]?.body?.isCharArray(harvest) ?: false
    else -> false
}

private fun TypeDecl<GlobalTypeId>.isCharType(harvest: Harvest): Boolean = when (this) {
    is TypeDecl.Const -> inner.isCharType(harvest)
    is TypeDecl.Volatile -> inner.isCharType(harvest)
    is TypeDecl.InlineDef -> body.isCharType(harvest)
    is TypeDecl.Ref -> harvest.typeAsts[id]?.body?.isCharType(harvest) ?: false
    // Any 1-byte integer element: cygwin's named `char` resolves through its Range body to
    // Byte, not Char. The printable-run guard in stringLiteralAt keeps binary byte[] as hex.
    else -> when (resolveBuiltin()) {
        is CharDataType, is ByteDataType, is SignedByteDataType -> true
        else -> false
    }
}

/** Render a Struct's body members for in-skeleton expansion: one bare C-style decl per entry. */
fun TypeDecl.Struct<GlobalTypeId>.renderFull(
    harvest: Harvest,
    program: Program,
    shortener: TemplateNameShortener? = null,
): List<String> {
    val funcByMangled = harvest.openFunctions.associateBy { it.name }
    val members: List<Pair<Access, String>> =
        fields.filter { !it.isStatic }.sortedBy { it.offsetBits }.map { f ->
            f.access to "${f.type.render(harvest, shortener = shortener)} ${f.name};  /* +${f.offsetBits / 8}B */"
        } + methods.mapNotNull { m ->
            m.mangled?.let { funcByMangled[it] }?.let { m.access to "${it.signature(program)};" }
        }

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
