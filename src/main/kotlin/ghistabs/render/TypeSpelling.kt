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

/** ` : public virtual Base, private Other`, or nothing: each base named bare, `A` and not `struct A`. */
fun TypeDecl.Aggregate<GlobalTypeId>.spellBases(types: TypeGraph, shortener: TemplateNameShortener?): String =
    Speller(types, shortener).let { speller ->
        bases.takeIf { it.isNotEmpty() }
            ?.joinToString(", ", prefix = " : ") {
                val virtual = if (it.isVirtual) "virtual " else ""
                "${it.access.name.lowercase()} $virtual${speller.className(it.type, emptySet())}"
            }
            .orEmpty()
    }

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

        is TypeDecl.InlineDef if t.inner is TypeDecl.XRef -> leaf(
            "${t.inner.kind.cxxKeyword()} ${tagName(t.inner, t.id)}",
            d,
            quals,
        )

        // gcc 10+ define a base type at its first use, `ro:(0,36)=r(0,36);0;037777777777;`, and name
        // it later: `unsigned int:t(0,36)`.
        is TypeDecl.InlineDef if t.inner.resolveBuiltin() != null && types.byId(t.id)?.name != null ->
            spell(TypeDecl.Ref(t.id), d, quals, seen)

        is TypeDecl.InlineDef -> spell(t.inner, d, quals, seen + t.id)

        is TypeDecl.Const -> spell(t.inner, d, "${quals}const ", seen)

        is TypeDecl.Volatile -> spell(t.inner, d, "${quals}volatile ", seen)

        // gcc ≤ 3.3's `int A::*` is a pointer to the member type that ≥ 3.4 spells alone.
        is TypeDecl.Pointer if types.isMemberPointee(t.inner) -> spell(t.inner, d, quals, seen)

        is TypeDecl.Pointer -> types.resolve<TypeDecl.Method<GlobalTypeId>>(t.inner)
            ?.let { memberFunction(it, d, quals, seen) }
            ?: spell(t.inner, prefix("*", t.inner, d, quals, seen), "", seen)

        is TypeDecl.Reference -> spell(t.inner, prefix("&", t.inner, d, quals, seen), "", seen)

        is TypeDecl.Member -> spell(t.inner, prefix("${className(t.cls, seen)}::*", t.inner, d, quals, seen), "", seen)

        // A qualified array is an array of qualified elements.
        is TypeDecl.Array -> spell(t.element, "$d[${t.declaredElements ?: ""}]", quals, seen)

        // Only a method's stab lists its parameters; a plain `f` records none, so `()`: unspecified.
        is TypeDecl.FreeFunction -> spell(t.ret, "$d(${params(t.params, seen)})", "", seen)

        // Its class belongs to a pointer to it, as `A::*`: alone, a method is its function type.
        is TypeDecl.Method -> spell(t.ret, "$d(${params(args(t), seen)})", "", seen)

        is TypeDecl.XRef -> leaf("${t.kind.cxxKeyword()} ${tagName(t)}", d, quals)

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

    /** A class, bare: `A::*`, not `struct A::*`. */
    fun className(cls: GlobalTypeDecl, seen: Set<GlobalTypeId>): String = when (cls) {
        is TypeDecl.InlineDef if cls.inner is TypeDecl.XRef -> tagName(cls.inner, cls.id)
        is TypeDecl.InlineDef -> className(cls.inner, seen + cls.id)
        is TypeDecl.XRef -> tagName(cls)
        else -> spell(cls, "", "", seen)
    }

    /**
     * `(0,177)=xsStack:` names the tag, but binds [id], and where this CU defines it the definition's name
     * is the one to spell: it alone says which instantiation, once gcc ≥ 4.3 drops the tag's arguments.
     */
    private fun tagName(xref: TypeDecl.XRef<GlobalTypeId>, id: GlobalTypeId? = null): String {
        val name = id?.let(types::byId)?.takeIf { it.body !is TypeDecl.XRef }?.name ?: xref.tagName
        return shortener?.shortenedOrNull(name) ?: name
    }

    /**
     * `ret (A::*d)(args)`, a pointer to member function of the method's class. gdb's stub method (`##ret;`)
     * states no class, so it is spelled as a plain function pointer.
     */
    private fun memberFunction(m: TypeDecl.Method<GlobalTypeId>, d: String, quals: String, seen: Set<GlobalTypeId>) =
        spell(
            m.ret,
            prefix(
                m.cls?.let {
                    "${className(it, seen)}::*"
                } ?: "*",
                m,
                d,
                quals,
                seen,
            ) + "(${params(args(m), seen)})",
            "",
            seen,
        )

    /** A method's own arguments: gcc lists `this` first where it states the class, and ends the list with `void`. */
    private fun args(m: TypeDecl.Method<GlobalTypeId>) = m.params
        .drop(if (m.cls != null) 1 else 0)
        .let { args ->
            if (args.lastOrNull()?.let { types.resolveAny(it) { t -> t == TypeDecl.Void } } ==
                true
            ) {
                args.dropLast(1)
            } else {
                args
            }
        }

    private fun params(params: List<GlobalTypeDecl>, seen: Set<GlobalTypeId>) =
        params.joinToString(", ") { spell(it, "", "", seen) }
}
