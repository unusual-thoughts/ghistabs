@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.index

import ghidra.program.model.data.CategoryPath
import ghistabs.diagnose.DiagnosticSink
import ghistabs.harvest.*
import ghistabs.parse.*
import kotlinx.serialization.Serializable

private fun TypeGraph.walksToUnresolvedRef(t: GlobalTypeDecl): Boolean = when (t) {
    is TypeDecl.Ref -> byId(t.id) == null
    else -> t.children.any { fields -> fields.any { walksToUnresolvedRef(it) } }
}

private fun TypeGraph.countUnresolvedRefs(body: GlobalTypeDecl): Int {
    if (body !is TypeDecl.Struct) return 0
    return body.fields.count { f -> walksToUnresolvedRef(f.type) }
}

/** Id of the struct/union [t] embeds by value (through Ref/InlineDef/Const/Volatile only, never a
 *  pointer/array), or null — the containment edge that scopes a method-less nested member type. */
private fun TypeGraph.byValueStructId(t: GlobalTypeDecl) = resolveWith(t) { d ->
    when (d) {
        is TypeDecl.Ref -> d.id.takeIf { byId(it)?.body is TypeDecl.Struct }
        is TypeDecl.InlineDef -> d.id.takeIf { d.inner is TypeDecl.Struct }
        else -> null
    }
}

/**
 * The member whose body best represents the group: largest body → most methods → fewest unresolved
 * Refs → [tiebreak] (stable, and the only criterion that can still tie).
 *
 * Members of a group are one content class, so their layouts — and therefore [TypeDecl.sizeBytes] —
 * are equal and the first criterion ties; the method count is what actually decides. It has to,
 * because methods and static fields are deliberately excluded from [content], so every per-CU copy
 * of a class compares equal however few methods it carries. The winner's body is the one that gets
 * materialized, and ClassBuilder reads its method list for vtable slots, `__thiscall` reparenting
 * and the namespace chain — so a method-poor winner silently loses those. Fewest-unresolved then
 * picks the most-resolved variant when CUs disagree on gcc-implicit slots.
 *
 * Shared by both winner selections (per-key in [classifyGroup], per-content-class in §B): they rank
 * different things — Types vs whole slots — but by one policy, which previously drifted apart.
 */
private fun <T> List<T>.pickWinner(index: TypeGraph, bodyOf: (T) -> GlobalTypeDecl, tiebreak: (T) -> String) = maxWith(
    compareBy<T> { bodyOf(it).sizeBytes }
        .thenBy { (bodyOf(it) as? TypeDecl.Struct)?.methods?.size ?: 0 }
        .thenByDescending { index.countUnresolvedRefs(bodyOf(it)) }
        .thenBy(tiebreak),
)

/**
 * The [TypeLocation] a type belongs at from its C++ scope alone — the `(category, name)` slot
 * [locateTypes] groups by, or null where the stabs give no scope and header attribution has to
 * answer instead.
 *
 * Two ways a scope is knowable. A method-bearing type carries its own: any member's mangled name
 * demangles to the full namespace chain, which is the same chain Ghidra's this-param class-struct
 * creator derives, so filing there means our filled type lands in the slot Ghidra would otherwise
 * forge empty. A method-less nested type (`_Alloc_hider`, `_Rep`, `sentry`) carries none, and is
 * recovered from its own `Outer::Inner` stab name or — failing that — from the struct that holds it
 * by value, then filed under that enclosing template's member category so it unifies with its
 * qualified sibling instead of forking a `.conflict`.
 */
class ScopeLocator(val index: TypeGraph) : DiagnosticSink by index {
    // Category each C++ class files its own nested members under, keyed by the class's canonicalised
    // stab name. Every method-bearing type contributes its own scope (`basic_string<char,…>` →
    // `/std/string`); method-less nested types below borrow it. Keyed by the stab name (not the
    // demangler leaf, which abbreviates `Ss`→`string`) because that is the spelling a nested type's
    // qualifier or its containing field carries; canonTemplateName erases the whitespace gcc varies.
    private val memberCategoryByClass: Map<String, CategoryPath> = buildMap {
        for (ast in index.allTypes) {
            val path = ast.demangledClassPath() ?: continue
            ast.name?.let { putIfAbsent(canonTemplateName(it), scopeCategory(path)) }
        }
    }

    // Reverse the by-value member edge: nested member type id → the struct that holds it as a field.
    // gcc emits `basic_string<char>::_Alloc_hider` both fully-qualified-with-methods (already
    // scoped) and bare-and-method-less; the bare one is only reachable as `basic_string._M_dataplus`.
    // Drop ids held by two distinct enclosers — no single owning scope.
    private val enclosingByNestedId: Map<GlobalTypeId, Type> = buildMap {
        val ambiguous = mutableSetOf<GlobalTypeId>()
        for (ast in index.allTypes) {
            val struct = ast.body as? TypeDecl.Struct ?: continue
            for (field in struct.fields) {
                if (field.isStatic) continue
                val nestedId = index.byValueStructId(field.type) ?: continue
                val prev = putIfAbsent(nestedId, ast)
                if (prev != null && prev.id != ast.id) ambiguous += nestedId
            }
        }
        ambiguous.forEach(::remove)
    }

    /**
     * The scope gcc *stated* for [ast], not one recovered from its surroundings.
     *
     * Method-bearing: any member's mangled name demangles to the full chain — the exact
     * `(category, name)` Ghidra's this-param class-struct creator uses (same GnuDemangler), so our
     * filled slot IS the slot it would otherwise forge empty. REQUIRES [TypeRegistry.register] to
     * replace Ghidra's empty namespace shadows (REPLACE_EMPTY_STRUCTS) — else `dtm.resolve` keeps the
     * empty shadow at the colliding path and every reference resolves to it (all-undef).
     *
     * Method-less, but some CU emitted an out-of-line member: the `this` param names this exact id and
     * the mangled name states the path (§57). Two instantiations of a nested template
     * (`AbstractRing<Integer>::MultiplicativeGroupT` and the `PolynomialMod2` one) share a leaf and
     * nothing else tells them apart, so without this they collapse onto one header key.
     */
    private fun statedLocation(ast: Type) = (ast.demangledClassPath() ?: index.classPathByThisParam[ast.id])
        ?.let { TypeLocation(scopeCategory(it.dropLast(1)), it.last()) }

    /**
     * Name, spelled base list and layout — enough to recognise the same class emitted by another CU.
     * The base *names* are the point: a CU that emitted no out-of-line member leaves its copy unbound,
     * but it still spells what the copy inherits (`ec2n.cpp`'s `MultiplicativeGroupT` derives from
     * `AbstractGroup<PolynomialMod2>`, `integer.cpp`'s from `AbstractGroup<Integer>`), and [content] is
     * blind to exactly that — it drops names, and the two bases are themselves layout-equal.
     */
    private data class Shape(val name: String, val bases: List<String?>?, val layout: ContentIndex.LayoutContent)

    private fun shapeOf(ast: Type) = Shape(ast.ghidraName, baseNames(ast), index.content(ast.body))

    private fun baseNames(ast: Type) = (ast.body as? TypeDecl.Struct)?.bases?.map { base ->
        index.resolveWith(base.type) {
            when (it) {
                is TypeDecl.XRef -> it.tagName
                is TypeDecl.Ref -> index.byId(it.id)?.name
                is TypeDecl.InlineDef -> index.byId(it.id)?.name
                else -> null
            }
        }
    }

    // Where an unbound copy goes: the slot a stated sibling of the same shape already occupies. This
    // only ever repeats a location, never picks one — a shape two stated locations claim is dropped,
    // because there the copy genuinely could be either.
    private val statedLocationByShape: Map<Shape, TypeLocation> = buildMap {
        val ambiguous = mutableSetOf<Shape>()
        for (ast in index.allTypes) {
            val location = statedLocation(ast) ?: continue
            val shape = shapeOf(ast)
            if (putIfAbsent(shape, location)?.takeIf { it != location } != null) ambiguous += shape
        }
        ambiguous.forEach(::remove)
    }

    fun scopeKey(ast: Type): TypeLocation? {
        statedLocation(ast)?.let { return it }

        // Method-less nested member type (`_Alloc_hider`, `_Rep`, `sentry`) — no mangled method to
        // scope it, so it otherwise collides char-vs-wchar under one bare-name header key. Recover the
        // enclosing template from its own `Outer::Inner` stab name, else from the struct that holds it
        // by value, and file it under that template's member category — the slot its qualified,
        // method-bearing sibling already occupies, so the two unify instead of forking a `.conflict`.
        val recovered = (
            ast.name?.let(::splitQualified)?.takeIf { it.size > 1 }
                ?.let { it.dropLast(1).joinToString("::") to it.last() }
                ?: enclosingByNestedId[ast.id]?.name?.let { it to ast.ghidraName }
            )?.let { (enclosingName, leaf) ->
            memberCategoryByClass[canonTemplateName(enclosingName)]?.let { TypeLocation(it, leaf) }
        }

        // Last: the slot a stated twin from another CU occupies (§57).
        return recovered ?: statedLocationByShape[shapeOf(ast)]?.also {
            debug("scope-from-twin", "${ast.ghidraName} (${ast.id.source.filename}) -> $it")
        }
    }

    fun classifyGroup(key: TypeLocation, members: List<Type>): LocatedType {
        val distinctKinds = members.map { it.body::class }.toSet()
        if (distinctKinds.size > 1) {
            warn("canonical-key-multi-kind", "$key: ${distinctKinds.map { it.simpleName }}")
        }
        val contentClasses = members.groupBy { index.content(it.body) }.values
        when {
            contentClasses.size > 1 -> debug(
                "canonical-key-multi-hash",
                "$key: ${contentClasses.size} distinct bodies across " +
                    members.map { it.id.source.filename }.toSet(),
            )

            members.size > 1 -> debug(
                "canonical-key-merged",
                "$key: ${members.size} ASTs collapsed (single body)",
            )
        }
        val winner = members.pickWinner(index, { it.body }, { it.id.source.filename })
        return LocatedType(key, winner, members.map { it.id }, contentClasses.size)
    }
}

/**
 * Canonical (category, ghidraName) → group; drives TypeRegistry slot assignment. XRef-targets are
 * bucketed into `(category, ghidraName)` slots ([classifyGroup] picks each winner), then slots are
 * unified by **content hash** (§20): gcc spells one header two ways, so one logical type lands in
 * several slots (named, anonymous copy, typedef aliases) → several DataTypes → the decompiler picks
 * the wrong same-named one. Within a content class holding exactly one named ghidraName, every slot —
 * anonymous ones included — collapses onto that name's largest slot. Content, not path, is the signal,
 * so it reaches headers that don't fold by basename; distinct-named or unnamed classes stay separate.
 */
fun TypeGraph.locateTypes(attribution: Attribution) = locateTypesWith(attribution)

/**
 * The assembly every real caller wants. An [Attribution] needs exactly two things — the graph's own
 * source prefix and the header vote — so building one is not a decision a caller should be making.
 * It had been inlined at the single production call site and copied verbatim into the scope tests,
 * which is what a missing name looks like.
 */
fun TypeGraph.locateTypes(hints: SourceHints) = locateTypesWith(
    Attribution(
        commonProjectPrefix = commonProjectPrefix(allTypes.map { it.id.source }),
        multiSourceHeaderHints = hints.multiSourceHeaderHints,
    ),
)

private fun TypeGraph.locateTypesWith(attribution: Attribution) = buildMap {
    val byGhidraName = allTypes.groupBy { it.ghidraName }
    fun Type.headerKey() = attribution.keyForAst(this, byGhidraName.getValue(ghidraName).map { it.id.source }.toSet())
    val nesting = ScopeLocator(this@locateTypesWith)

    // Scope→header→hash ladder. A type whose enclosing C++ scope is derivable (any member's
    // mangled name yields one) files under that namespace category — matching where Ghidra's
    // this-param class-struct creator looks, so our filled type is the one it reuses instead of
    // synthesizing an empty stub. Header attribution is the fallback for method-less types (C
    // aggregates, gcc anonymous copies) AND the collision-breaker: a scope key holding genuinely
    // divergent content (same (scope,name), several bodies) demotes each body to its header key.
    val slots = allTypes
        .filter { it.body.isXRefTarget }
        .groupBy(nesting::scopeKey)
        .flatMap { (scopeKey, members) ->
            if (scopeKey == null) {
                members.groupBy { it.headerKey() }.map { (k, ms) -> nesting.classifyGroup(k, ms) }
            } else {
                // Divergence is decided by the scope-owning (method-bearing) members alone. A
                // method-less nested type recovered into this slot is the same type as its qualified
                // sibling — layout-identical, differing only in emitted methods, which never enter the
                // DTM struct — so it rides along and aliases onto the owners' winner instead of forking
                // the group. Genuine divergence among the owners still demotes every member to header.
                // Method-bearing only, even though an out-of-line member states a scope just as firmly
                // (§57): a body that declares methods is the one whose *content* is worth comparing.
                // Counting the bound-but-method-less copies as owners put every CU's stub declaration of
                // `std::type_info` in the vote, they diverge, and the demotion emptied `/std/type_info` —
                // the slot Ghidra's demangler had already forged and was waiting for us to fill.
                val owners = members.filter { it.demangledClassPath() != null }.ifEmpty { members }
                // Layout-only: owners diverge only in per-CU method flags/order (gcc VIRTUAL vs NORMAL,
                // reordering), which never enter the DTM struct — don't let that noise demote the group.
                if (owners.groupBy { content(it.body) }.size == 1) {
                    val group = nesting.classifyGroup(scopeKey, owners)
                    listOf(if (owners.size == members.size) group else group.copy(members = members.map { it.id }))
                } else {
                    debug("canonical-scope-collision", "$scopeKey: divergent bodies → demoted to header keys")
                    members.groupBy { it.headerKey() }.map { (k, ms) -> nesting.classifyGroup(k, ms) }
                }
            }
        }

    // §B: merge by layout, not content — a class's method-less header/`multi` copies share the
    // scope-keyed method-bearing copy's layout (methods never enter the DTM struct), so they fold
    // onto it instead of forking a duplicate slot. The `ghidraName` guard keeps genuinely
    // different same-layout classes apart; the winner prefers the method-bearing copy.
    // Layout is blind to template arguments: `AbstractRing<Integer>::MultiplicativeGroupT` and its
    // `PolynomialMod2` sibling are one LayoutContent (same fields, and their bases are layout-equal
    // too), so §B would fold straight back together what §57's scope key just separated. A stated
    // scope outranks a layout match — two of them are two declared types. Their method-less copies
    // then have two candidates and nothing to choose with, so they keep their own slot rather than
    // being guessed onto one.
    fun LocatedType.isScopeStated() = location == nesting.scopeKey(type)

    for (equivalent in slots.groupBy { content(it.type.body) }.values) {
        val named = equivalent.filter { it.type.name != null }
        if (equivalent.size == 1 ||
            equivalent.count { it.isScopeStated() } > 1 ||
            named.map { it.type.ghidraName }.toSet().size != 1
        ) {
            for (g in equivalent) put(g.location, g)
            continue
        }
        // Same layout ⇒ same size, so the size tiebreak ties here; the method count decides, which
        // is what makes the scope-keyed method-bearing copy win over a method-less one.
        val winner = named.pickWinner(this@locateTypesWith, { it.type.body }, { it.location.toString() })
        debug(
            "canonical-content-merged",
            "${winner.location}: ${equivalent.size} groups (${
                equivalent.count { it.type.name == null }
            } anon) across ${equivalent.map { it.location.category }.toSet()}",
        )
        put(
            winner.location,
            winner.copy(members = equivalent.flatMap { it.members }),
        )
    }
}

@Serializable(with = ToStringSerializer::class)
data class TypeLocation(val category: CategoryPath, val name: String) {
    constructor(path: String, name: String) : this(CategoryPath(path), name)

    override fun toString() = "$category/$name"
}

/**
 *  Types with the same [location] collapsed onto one DTM slot.
 *  [type] is the one chosen to materialize
 *  [members] and [distinct] are for diagnostics.
 *  [members] contains all the harvested [Type]s that located there, and
 *  [distinct] is the count of truly different types among them according to [ContentIndex]
 */
@Serializable
data class LocatedType(val location: TypeLocation, val type: Type, val members: List<GlobalTypeId>, val distinct: Int)
