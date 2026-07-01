package ghistabs.render

import ghidra.program.model.listing.Program
import ghistabs.harvest.Harvest
import ghistabs.materialize.BuiltinTable
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl

/**
 * Best-effort C-style rendering of a [TypeDecl]. Primitives go
 * through [BuiltinTable] so they come out as `int` / `uchar` /
 * `double` etc; named composite types are looked up by id in
 * [Harvest.typeAsts]. Cycles (gcc's recursive
 * `std::basic_string<…>::operator=` taking `std::string&`) are broken
 * with a visited-set of the type ids on the current path — NOT a depth
 * cap, which the transparent Ref/InlineDef indirections would exhaust
 * on legitimately deep types (e.g. an array of const char pointers:
 * Array→InlineDef→Const→Ref→Pointer→Ref→Const→Ref→char).
 */
fun TypeDecl<GlobalTypeId>.render(harvest: Harvest, seen: Set<GlobalTypeId> = emptySet()): String = when (this) {
    is TypeDecl.Ref -> {
        // Named TypeAst → use the name. Anonymous → recurse into its body so the
        // user sees `int *` rather than a raw GlobalTypeId, unless this id is
        // already on the path (cycle). Unresolved (cross-CU dangling) → id string.
        val ast = harvest.typeAsts[id]
        val name = ast?.name
        when {
            name != null -> name
            ast == null -> "T_$id"
            id in seen -> "…"
            else -> ast.body.render(harvest, seen + id)
        }
    }

    is TypeDecl.Pointer -> "${pointee.render(harvest, seen)} *"

    is TypeDecl.Reference -> "${referent.render(harvest, seen)} &"

    is TypeDecl.Const -> "${inner.render(harvest, seen)} const"

    is TypeDecl.Volatile -> "${inner.render(harvest, seen)} volatile"

    is TypeDecl.Array -> {
        // gcc stores the bound in indexType (`ar<idx>;lo;hi`), leaving length null;
        // derive count as hi-lo+1, same as TypeRegistry's array materialization.
        val len = length ?: (indexType as? TypeDecl.Range)?.let { it.max - it.min + 1 }
        "${element.render(harvest, seen)}[${len ?: ""}]"
    }

    is TypeDecl.Builtin,
    is TypeDecl.Range,
    is TypeDecl.Float,
    is TypeDecl.Complex,
    is TypeDecl.WithSizeAttr,
    -> BuiltinTable.resolve(this)?.name ?: this::class.simpleName?.lowercase() ?: "?"

    is TypeDecl.XRef -> "${kind.cxxKeyword()} $tagName"

    is TypeDecl.Struct -> kind.cxxKeyword()

    is TypeDecl.Enum -> "enum"

    is TypeDecl.FunctionT -> {
        val ret = ret.render(harvest, seen)
        val params = params.joinToString(", ") { it.render(harvest, seen) }
        "$ret($params)"
    }

    is TypeDecl.Method -> {
        val cls = cls.render(harvest, seen)
        val ret = ret.render(harvest, seen)
        val params = params.joinToString(", ") { it.render(harvest, seen) }
        "$ret($cls::*)($params)"
    }

    is TypeDecl.InlineDef -> body.render(harvest, seen + id)
}

/** Render a Struct's body members for in-skeleton expansion: one bare C-style decl per entry. */
fun TypeDecl.Struct<GlobalTypeId>.renderFull(harvest: Harvest, program: Program): List<String> {
    val fieldLines = fields
        .filter { !it.isStatic }
        .sortedBy { it.offsetBits }
        .map { f ->
            val type = f.type.render(harvest)
            "$type ${f.name};  /* +${f.offsetBits / 8}B */"
        }
    val funcByMangled = harvest.openFunctions.associateBy { it.name }
    val methodLines = methods.mapNotNull { m ->
        m.mangled?.let { mangled ->
            funcByMangled[mangled]?.let { func ->
                "${func.signature(program)};"
            }
        }
    }
    return fieldLines + methodLines
}
