@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.index

import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataTypePath
import ghistabs.cpp.canonTemplateName
import ghistabs.cpp.enclosingName
import ghistabs.cpp.leafName
import ghistabs.diagnose.DiagnosticSink
import ghistabs.harvest.Type
import ghistabs.parse.GlobalTypeDecl
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.ToStringSerializer
import ghistabs.parse.TypeDecl
import kotlinx.serialization.Serializable

private fun TypeGraph.walksToUnresolvedRef(t: GlobalTypeDecl): Boolean = when (t) {
    is TypeDecl.Ref -> byId(t.id) == null
    else -> t.children.any { fields -> fields.any { walksToUnresolvedRef(it) } }
}

private fun TypeGraph.countUnresolvedRefs(body: GlobalTypeDecl): Int {
    if (body !is TypeDecl.Aggregate) return 0
    return body.fields.count { f -> walksToUnresolvedRef(f.type) }
}

/**
 * Id of the struct or union [t] embeds by value (through Ref, InlineDef, Const and Volatile, never a
 * pointer or array), or null: the containment edge that scopes a method-less nested member type.
 */
private fun TypeGraph.byValueStructId(t: GlobalTypeDecl) = resolveWith(t) { d ->
    when (d) {
        is TypeDecl.Ref -> d.id.takeIf { byId(it)?.body is TypeDecl.Aggregate }
        is TypeDecl.InlineDef -> d.id.takeIf { d.inner is TypeDecl.Aggregate }
        else -> null
    }
}

/**
 * The member whose body is materialized for the group: largest body, then most methods, then fewest
 * unresolved Refs, then [tiebreak]. Copies of one class share a layout, since [ContentIndex.content]
 * leaves methods out, so the method count usually decides; ClassApplier reads the winner's methods
 * for vtable slots, `__thiscall` and the namespace chain.
 */
private fun <T> List<T>.pickWinner(index: TypeGraph, bodyOf: (T) -> GlobalTypeDecl, tiebreak: (T) -> String) = maxWith(
    compareBy<T> { bodyOf(it).sizeBytes }
        .thenBy { (bodyOf(it) as? TypeDecl.Aggregate)?.methods?.size ?: 0 }
        .thenByDescending { index.countUnresolvedRefs(bodyOf(it)) }
        .thenBy(tiebreak),
)

/**
 * Each type's [TypeLocation] from its C++ scope ([scopeKey]), and the slots [locateTypes] merges.
 *
 * A method-bearing type's mangled members demangle to the namespace chain Ghidra's this-param
 * class-struct creator uses, so filing there fills the slot Ghidra would make empty. A method-less
 * nested type (`_Alloc_hider`, `_Rep`, `sentry`) is scoped from its `Outer::Inner` stab name, else
 * from the struct holding it by value, so it unifies with its qualified sibling.
 */
class ScopeLocator(val index: TypeGraph) : DiagnosticSink by index {
    // The category each method-bearing class files its nested members under (`basic_string<char,…>` is
    // `/std/string`), by canonical stab name: a nested type's qualifier spells the stab name, and gcc
    // varies its whitespace.
    private val memberCategoryByClass: Map<String, CategoryPath> = buildMap {
        for (ast in index.allTypes) {
            val path = ast.demangledClassPath() ?: continue
            ast.name?.let { putIfAbsent(canonTemplateName(it), scopeCategory(path)) }
        }
    }

    // The struct holding each nested type by value. gcc also emits `basic_string<char>::_Alloc_hider`
    // bare and method-less, reachable only as `basic_string._M_dataplus`. Ids two structs hold are dropped.
    private val enclosingByNestedId: Map<GlobalTypeId, Type> = buildMap {
        val ambiguous = mutableSetOf<GlobalTypeId>()
        for (ast in index.allTypes) {
            val struct = ast.body as? TypeDecl.Aggregate ?: continue
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
     * The scope gcc stated for [ast]: its members' demangled class path, or for a method-less copy, the
     * path of an out-of-line member whose `this` names it (§57). Only the latter tells apart nested
     * template instantiations sharing a leaf (`AbstractRing<Integer>::MultiplicativeGroupT`).
     *
     * Requires [ghistabs.DtmRegistry.register] to replace Ghidra's empty namespace structs, or every reference
     * resolves to the empty one at the same path.
     */
    private fun statedLocation(ast: Type) = (ast.demangledClassPath() ?: index.classPathByThisParam[ast.id])
        ?.let { TypeLocation(scopeCategory(it.dropLast(1)), it.last()) }

    /**
     * Leaf name, base names and layout: enough to recognise one class across CUs. Base names tell apart
     * layout-equal copies (`ec2n.cpp`'s `MultiplicativeGroupT` derives from `AbstractGroup<PolynomialMod2>`,
     * `integer.cpp`'s from `AbstractGroup<Integer>`). The leaf matches a bare `sentry` with its qualified
     * `basic_istream<char,…>::sentry` twin.
     */
    private data class Shape(val name: String, val bases: List<String?>?, val layout: ContentIndex.LayoutContent)

    private fun shapeOf(ast: Type) =
        Shape(ast.name?.leafName ?: ast.ghidraName, baseNames(ast), index.content(ast.body))

    private fun baseNames(ast: Type) =
        (ast.body as? TypeDecl.Aggregate)?.bases?.map { index.targetXRef(it.type)?.tagName?.leafName }

    // The stated location of each shape. A shape with two stated locations is dropped.
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

        // A method-less nested type files under its enclosing template's member category, found from its
        // `Outer::Inner` stab name or the struct holding it, so char and wchar_t copies stay apart.
        val recovered = (
            ast.name?.let { n -> n.enclosingName?.let { it to n.leafName } }
                ?: enclosingByNestedId[ast.id]?.name?.let { it to ast.ghidraName }
            )?.let { (enclosingName, leaf) ->
            memberCategoryByClass[canonTemplateName(enclosingName)]?.let { TypeLocation(it, leaf) }
        }

        // Else the slot a stated twin from another CU occupies (§57).
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

    /**
     * Reports the [members] smaller than [winner]: they materialize as the winner, longer than their own
     * stab and with its fields, as when two winnt.h versions disagree on `_REPARSE_DATA_BUFFER`.
     */
    fun reportSmallerBodies(key: TypeLocation, winner: Type, members: List<Type>) {
        val size = (winner.body as? TypeDecl.Aggregate)?.sizeBytes ?: return
        val smaller = members.filter { ((it.body as? TypeDecl.Aggregate)?.sizeBytes ?: size) < size }
        if (smaller.isEmpty()) return
        val bySize = smaller.groupBy({ (it.body as TypeDecl.Aggregate).sizeBytes }, { it.id.source.filename })
            .map { (bytes, files) -> "$bytes bytes in ${files.toSet().joinToString()}" }
        degradation(
            "struct-longer-than-stab",
            key.toString(),
            "$size-byte body from ${winner.id.source.filename} stands in for ${bySize.joinToString()}",
        )
    }

    /** Members keyed together, and the voters their winner is picked from: a kept scope's owners, or the member. */
    private class TypeSlot(val voters: List<Type>, val members: List<Type>) {
        constructor(single: Type) : this(listOf(single), listOf(single))

        companion object {
            /**
             * One slot for a scope key's [members], or null when its owners, the method-bearing members,
             * diverge. Each CU's method-less stub of `std::type_info` differs, so method-less members only
             * ride along. Methods never enter [ContentIndex.content], so per-CU method flags don't count.
             */
            fun scopedFrom(members: List<Type>, graph: TypeGraph): TypeSlot? =
                when (val owners = members.filter { it.demangledClassPath() != null }.ifEmpty { members }) {
                    else if owners.distinctBy { graph.content(it.body) }.size == 1 -> TypeSlot(owners, members)
                    else -> null
                }
        }
    }

    // A header key's voters: every copy of a type, by name and size. Size keeps istream's 1-byte bare
    // `sentry` apart from ostream's 8-byte one; layout would split copies of one class whose CUs knew
    // different amounts of a referenced class.
    private val sourcesOfCopies by lazy {
        index.allTypes.groupBy({ it.ghidraName to it.body.sizeBytes }, { it.id.source })
    }

    private fun keyed(attribution: Attribution): Map<TypeLocation, List<TypeSlot>> {
        fun Type.headerKey() =
            attribution.keyForAst(this, sourcesOfCopies.getValue(ghidraName to body.sizeBytes).toSet())

        return index.allTypes.asSequence()
            .filter { it.body.canBeXRefTarget }
            .groupBy(::scopeKey)
            .flatMap { (scopeKey, members) ->
                when (scopeKey) {
                    null -> members.map { it.headerKey() to TypeSlot(it) }

                    else -> TypeSlot.scopedFrom(members, index)?.let { listOf(scopeKey to it) } ?: run {
                        // Two classes share the name: each member goes to its header, its namespace kept below.
                        debug("canonical-scope-collision", "$scopeKey: divergent bodies → demoted to header keys")
                        members.map { it.headerKey().within(scopeKey.category) to TypeSlot(it) }
                    }
                }
            }.groupBy({ it.first }, { it.second })
    }

    /**
     * One [LocatedType] per location: a type with a scope files under its namespace, any other under its
     * header. A demoted body and a scope-less copy of the same name meet in one slot.
     */
    internal fun slots(attribution: Attribution) = keyed(attribution).map { (location, slots) ->
        val members = slots.flatMap { it.members }
        classifyGroup(location, slots.flatMap { it.voters })
            .copy(members = members.map { it.id })
            .also { reportSmallerBodies(location, it.type, members) }
    }
}

/**
 * Every xref-target type's DTM slot. Slots of one layout and at most one name then fold together,
 * anonymous copies included (§20): gcc spells one header two ways, and each spelling would otherwise
 * be its own DataType for the decompiler to pick from.
 */
fun TypeGraph.locateTypes(hints: SourceHints) = ScopeLocator(this).locateTypesWith(
    Attribution(
        commonProjectPrefix = commonProjectPrefix(allTypes.map { it.id.source }),
        multiSourceHeaderHints = hints.multiSourceHeaderHints,
    ),
)

private fun ScopeLocator.locateTypesWith(attribution: Attribution): Map<TypeLocation, LocatedType> = buildMap {
    fun LocatedType.isScopeStated() = location == scopeKey(type)

    // §B. Layout ignores template arguments, so two stated scopes of one layout, and their method-less
    // copies, stay apart (`AbstractRing<Integer>::MultiplicativeGroupT` and its `PolynomialMod2` sibling, §57).
    for (equivalent in slots(attribution).groupBy { index.content(it.type.body) }.values) {
        val named = equivalent.filter { it.type.name != null }
        if (equivalent.size == 1 ||
            equivalent.count { it.isScopeStated() } > 1 ||
            named.map { it.type.ghidraName }.toSet().size != 1
        ) {
            for (g in equivalent) put(g.location, g)
            continue
        }
        // Same layout means same size, so the method count decides and the method-bearing copy wins.
        val winner = named.pickWinner(index, { it.type.body }, { it.location.toString() })
        debug(
            "canonical-content-merged",
            "${winner.location}: ${equivalent.size} groups (${
                equivalent.count { it.type.name == null }
            } anon) across ${equivalent.map { it.location.category }.toSet()}",
        )
        put(winner.location, winner.copy(members = equivalent.flatMap { it.members }))
    }
}

@Serializable(with = ToStringSerializer::class)
data class TypeLocation(val category: CategoryPath, val name: String) : DataTypePath(category, name) {
    constructor(path: String, name: String) : this(CategoryPath(path), name)

    override fun toString() = "$category/$name"

    /** This location with [scope] below its category, which Ghidra's class-struct lookup matches by tail. */
    fun within(scope: CategoryPath) = TypeLocation(category.extend(*scope.pathElements), name)
}

/**
 * The types at one [location], collapsed onto one DTM slot: [type] is materialized. For diagnostics,
 * [members] are every type located there and [distinct] the number of distinct bodies among them.
 */
@Serializable
data class LocatedType(val location: TypeLocation, val type: Type, val members: List<GlobalTypeId>, val distinct: Int)
