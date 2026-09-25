package ghistabs.render

import ghistabs.index.TypeGraph
import ghistabs.materialize.TemplateNameShortener
import ghistabs.materialize.resolveBuiltin
import ghistabs.parse.GlobalTypeDecl
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl

/**
 * The C spelling of a type with [name] declared as it, or of the type alone when [name] is empty.
 * C declarators read inside out — `char (*(*x[3])())[5]` — so the name is threaded down the type rather
 * than appended: a pointer prefixes it, an array or function suffixes it, and a pointer to an array or
 * function is parenthesized so the suffix binds to the pointer. Qualifiers stay to the right of what
 * they qualify (`char const *const p`).
 *
 * Cycles (gcc's recursive `std::basic_string<…>::operator=` taking `std::string&`) break on the type
 * ids already on the path, not on depth: the transparent Ref/InlineDef hops would exhaust any cap on
 * a legitimately deep type.
 */
fun GlobalTypeDecl.spell(name: String, types: TypeGraph, shortener: TemplateNameShortener?): String =
    Speller(types, shortener).spell(this, name, "", emptySet())

private class Speller(val types: TypeGraph, val shortener: TemplateNameShortener?) {
    fun spell(t: GlobalTypeDecl, d: String, quals: String, seen: Set<GlobalTypeId>): String = when (t) {
        TypeDecl.Void -> leaf("void", d, quals)

        // Named → its name. Anonymous → its body, unless already on the path. Dangling → the id.
        is TypeDecl.Ref -> {
            val ast = types.byId(t.id)
            val name = ast?.name
            when {
                name != null -> leaf(shortener?.shortenedOrNull(name) ?: name, d, quals)
                ast == null -> leaf("T_${t.id}", d, quals)
                t.id in seen -> leaf("…", d, quals)
                else -> spell(ast.body, d, quals, seen + t.id)
            }
        }

        is TypeDecl.InlineDef -> spell(t.inner, d, quals, seen + t.id)

        is TypeDecl.Const -> spell(t.inner, d, "${quals}const ", seen)

        is TypeDecl.Volatile -> spell(t.inner, d, "${quals}volatile ", seen)

        // gcc ≤ 3.3's `int A::*` is a pointer to the member type that ≥ 3.4 spells alone.
        is TypeDecl.Pointer if types.isMemberPointee(t.inner) -> spell(t.inner, d, quals, seen)

        is TypeDecl.Pointer -> spell(t.inner, prefix("*", t.inner, d, quals, seen), "", seen)

        is TypeDecl.Reference -> spell(t.inner, prefix("&", t.inner, d, quals, seen), "", seen)

        is TypeDecl.Member -> spell(t.type, prefix("${className(t.cls, seen)}::*", t.type, d, quals, seen), "", seen)

        // A qualified array is an array of qualified elements.
        is TypeDecl.Array -> spell(t.element, "$d[${t.declaredElements ?: ""}]", quals, seen)

        // Only a method's stab lists its parameters; a plain `f` records none, so `()`: unspecified.
        is TypeDecl.FreeFunction -> spell(t.ret, "$d(${params(t.params, seen)})", "", seen)

        is TypeDecl.Method -> {
            val cls = t.cls?.let { className(it, seen) }.orEmpty()
            spell(t.ret, "($cls::*$d)(${params(t.params, seen)})", "", seen)
        }

        is TypeDecl.XRef -> leaf(
            "${t.kind.cxxKeyword()} ${shortener?.shortenedOrNull(t.tagName) ?: t.tagName}",
            d,
            quals,
        )

        is TypeDecl.Aggregate -> leaf(t.cxxKeyword, d, quals)

        is TypeDecl.Enum -> leaf("enum", d, quals)

        is TypeDecl.Builtin,
        is TypeDecl.Range,
        is TypeDecl.Float,
        is TypeDecl.Complex,
        is TypeDecl.WithSizeAttr,
        -> leaf(t.resolveBuiltin()?.name ?: t::class.simpleName?.lowercase() ?: "?", d, quals)
    }

    private fun leaf(base: String, d: String, quals: String) =
        "$base${if (quals.isEmpty()) "" else " ${quals.trim()}"}" + when {
            d.isEmpty() || d.startsWith('[') -> d
            else -> " $d"
        }

    /** `*`, `&` or `A::*` ahead of [d], qualified, and parenthesized when [pointee] would bind tighter. */
    private fun prefix(op: String, pointee: GlobalTypeDecl, d: String, quals: String, seen: Set<GlobalTypeId>) =
        "$op${quals.trim().let { if (it.isEmpty() || d.isEmpty()) it else "$it " }}$d"
            .let { if (bindsTighter(pointee, seen)) "($it)" else it }

    /** An array's `[]` or a function's `()` would otherwise attach to the name, not to the pointer. */
    private fun bindsTighter(t: GlobalTypeDecl, seen: Set<GlobalTypeId>): Boolean = when (t) {
        is TypeDecl.Array, is TypeDecl.FreeFunction, is TypeDecl.Method -> true

        is TypeDecl.InlineDef -> bindsTighter(t.inner, seen + t.id)

        is TypeDecl.Const -> bindsTighter(t.inner, seen)

        is TypeDecl.Volatile -> bindsTighter(t.inner, seen)

        // A named type is spelled by its name, which binds like any identifier.
        is TypeDecl.Ref -> types.byId(t.id)
            ?.takeIf { it.name == null && t.id !in seen }
            ?.let { bindsTighter(it.body, seen + t.id) } == true

        else -> false
    }

    /** A member pointer's class, bare: `A::*`, not `struct A::*`. */
    private fun className(cls: GlobalTypeDecl, seen: Set<GlobalTypeId>): String = when (cls) {
        is TypeDecl.InlineDef -> className(cls.inner, seen + cls.id)
        is TypeDecl.XRef -> shortener?.shortenedOrNull(cls.tagName) ?: cls.tagName
        else -> spell(cls, "", "", seen)
    }

    private fun params(params: List<GlobalTypeDecl>, seen: Set<GlobalTypeId>) =
        params.joinToString(", ") { spell(it, "", "", seen) }
}
