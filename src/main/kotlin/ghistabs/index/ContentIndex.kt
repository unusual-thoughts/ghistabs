package ghistabs.index

import ghistabs.diagnose.DiagnosticSink
import ghistabs.harvest.Type
import ghistabs.materialize.ghidraClass
import ghistabs.parse.GlobalTypeDecl
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl
import ghistabs.parse.TypeDecl.Aggregate.Base
import ghistabs.parse.TypeDecl.Aggregate.Field
import ghistabs.parse.leafName
import java.util.*

/**
 * Two-way oracle used by [content]: id-keyed lookup for [TypeDecl.Ref], plus name+kind lookup so a
 * `XRef(STRUCT, "Foo")` resolves to the same struct content as a `Ref(id_of_Foo)`. Is a
 * [DiagnosticSink] so resolution failures are reported where they are detected.
 */
abstract class ContentIndex(val contentCache: MutableMap<GlobalTypeId, LayoutContent> = mutableMapOf()) :
    DiagnosticSink {
    abstract fun byId(id: GlobalTypeId): Type?
    abstract fun byXRef(xref: TypeDecl.XRef<GlobalTypeId>): Type?

    /**
     * The name [decl] spells its target with — an id's own name, or a cross-reference's tag — through
     * the wrappers that keep it the same type. Null where the declaration names nothing (a primitive,
     * a pointer, an inline aggregate body).
     *
     * The *spelling*, which is not always the materialized DataType's name: a cross-reference no CU
     * defines gets its target named after the alias itself (`materializeTypedefs` §20), while every
     * composite name built from the AST goes on carrying the tag. Both readers of typedef aliases —
     * the DTM rename pass and the skeleton renderer, which never sees a DataType — need the tag.
     */
    fun targetSpelling(decl: GlobalTypeDecl): String? = when (decl) {
        is TypeDecl.Ref -> byId(decl.id)?.name
        is TypeDecl.XRef -> decl.tagName
        is TypeDecl.InlineDef -> targetSpelling(decl.inner)
        else -> null
    }

    /**
     * walks [decl] through `Ref`/`XRef`/`InlineDef` indirection and cv-wrappers to the first body
     * [pick] accepts, or null. `Pointer`/`Reference` are terminals: `Foo *` does not name a `Foo`.
     *
     * An `InlineDef` tries the ast registered at its id before the body spliced in at the use site,
     * which is frequently itself a forward `XRef` — without the preference, polymorphism detection
     * misses inherited vfptrs (`Cat` → `InlineDef(Animal id, XRef body)`) — and falls back to that
     * body when the id leads nowhere, without which a base whose id no CU defined reads as no base.
     */
    fun <R : Any> resolveWith(
        decl: GlobalTypeDecl,
        visited: MutableSet<GlobalTypeId> = mutableSetOf(),
        pick: (GlobalTypeDecl) -> R?,
    ): R? {
        pick(decl)?.let { return it }
        fun step(next: GlobalTypeDecl?) = next?.let { resolveWith(it, visited, pick) }
        fun stepId(id: GlobalTypeId) = if (visited.add(id)) step(byId(id)?.body) else null
        return when (decl) {
            is TypeDecl.Ref -> stepId(decl.id)
            is TypeDecl.XRef -> byXRef(decl)?.takeIf { visited.add(it.id) }?.let { step(it.body) }
            is TypeDecl.InlineDef -> stepId(decl.id) ?: step(decl.inner)
            is TypeDecl.Const -> step(decl.inner)
            is TypeDecl.Volatile -> step(decl.inner)
            else -> null
        }
    }

    /**
     * [targetSpelling]'s counterpart for a whole tag: the class, union or enum [decl] names through
     * typedefs and cv-qualifiers, as a cross-reference to its definition (or to the bare tag when no
     * definition resolves); null for an unnamed or CU-local definition.
     */
    fun targetXRef(decl: GlobalTypeDecl): TypeDecl.XRef<GlobalTypeId>? = resolveWith(decl) { d ->
        when (d) {
            is TypeDecl.XRef -> byXRef(d).let { if (it == null) d else it.asXRef() }
            else -> d.id?.let(::byId)?.asXRef()
        }
    }

    private fun Type.asXRef(): TypeDecl.XRef<GlobalTypeId>? {
        val kind = body.xrefKind ?: return null
        return name?.takeUnless { isCuLocalName() }?.let { TypeDecl.XRef(kind, it) }
    }

    /**
     * Canonical layout of a [TypeDecl] tree, as a value: equal [LayoutContent] ⇔ layout-equivalent
     * types. One traversal serves both grouping and equality, so the two cannot drift apart.
     *
     * Differences from `data class equals()` on the TypeDecl itself:
     *  - Id-bearing nodes (`Ref`, `InlineDef.id`) resolve to the referenced body, so `Ref(id)` and
     *    inline `InlineDef(id, body)` forms (gcc emits either depending on per-CU history) collapse to
     *    the same content.
     *  - A pointer or reference to a named class is keyed by the class's kind and leaf name, and
     *    const and volatile contribute nothing.
     *  - `Ref`/`InlineDef` wrappers contribute no node — they reduce to their wrapped content.
     *  - Primitives reduce to the Ghidra type they materialize to, so every stab spelling of `char`
     *    agrees regardless of source CU.
     *  - Struct methods and static fields are dropped (see the Struct branch), so layout-identical
     *    classes compare equal across CUs regardless of per-CU method virt/order noise.
     *
     * Cycles break via [visited]: a re-entry yields the empty back-edge marker. [contentCache] memoizes
     * successful (non-back-edge) results per id, which is also what makes the graph shared.
     */
    fun content(decl: GlobalTypeDecl, visited: Set<GlobalTypeId> = emptySet()) = decl.describe(visited)

    private fun GlobalTypeDecl.describe(visited: Set<GlobalTypeId> = emptySet()): LayoutContent = when (this) {
        is TypeDecl.Ref -> refKey(id, visited)

        // A pointer's layout is its own width, so a named pointee is keyed by its name, and by leaf: plain
        // `-gstabs` spells a nested class bare (`_Callback_list`), GNU extensions qualify it. By value nothing
        // contains itself, and methods and static fields are dropped below, so this cuts every cycle through
        // named classes; one through an unnamed or CU-local class still breaks where the walk entered it.
        is TypeDecl.Pointer, is TypeDecl.Reference -> wrapped?.let(::targetXRef)
            ?.let { LayoutContent(javaClass, listOf(it.kind, it.tagName.leafName)) }
            ?: layoutContent(visited)

        // Plain `-gstabs` drops const and volatile (dbxout.c), and neither changes a layout.
        is TypeDecl.Const, is TypeDecl.Volatile -> wrapped!!.describe(visited)

        TypeDecl.Void, is TypeDecl.Float, is TypeDecl.Complex, is TypeDecl.Enum, // no children
        is TypeDecl.Array, is TypeDecl.FreeFunction, is TypeDecl.Member, // two children
        is TypeDecl.Method, // three children
        -> layoutContent(visited)

        // Source-independent: same slot in every CU = same primitive. Reduce to the Ghidra type the
        // stab materializes to (see [ghidraClassName]), so char's `Range(0,127)` / `@s8;` Range /
        // `Builtin(-2)` spellings are one value and don't fork a `.conflict`. A shape that maps to no
        // primitive falls through to its structural content.
        is TypeDecl.Builtin, is TypeDecl.Range ->
            ghidraClass()?.let { LayoutContent(it) } ?: layoutContent(visited)

        // The DTM struct has no static members or methods, and both are cycle sources (libstdc++
        // `basic_string ↔ _Rep` recurse through static `_S_empty_rep_storage` and method signatures) —
        // including them makes the traversal-order back-edge land on different nodes per CU, forking
        // `.conflict` on layout-identical types. gcc also emits a virtual as VIRTUAL (vtoff set) in its
        // defining CU and NORMAL elsewhere, reordering methods per CU. So static fields and methods are
        // dropped: a layout-identical class is one value everywhere. So is the `~%` vptr owner, which
        // plain `-gstabs` never emits.
        is TypeDecl.Aggregate -> LayoutContent(
            javaClass,
            layoutData,
            listOf(
                bases.map { it.layoutContent(visited) },
                fields.filter { !it.isStatic }.map { it.layoutContent(visited) },
            ),
        )

        // Resolve XRef to its struct definition so a forward-declaration-only CU yields the same content
        // for any surrounding type as a full-definition CU. Falls back to (kind, tagName) — its own
        // layoutData — when truly unresolved.
        is TypeDecl.XRef -> byXRef(this)?.id?.let { refKey(it, visited) } ?: layoutContent(visited)

        // Skip the visited guard when body is an XRef: byXRef resolution must still be able to
        // add the resolved id to `visited` naturally. Without this, the pattern
        //   InlineDef(id=B, body=XRef(STRUCT, Foo))   resolving to id=B's own Struct
        // would pre-mark B and make refKey(B) return the empty back-edge marker instead of struct content.
        // For non-XRef bodies the guard IS required (a Ref(id) in a Struct body must not recurse).
        is TypeDecl.InlineDef -> inner.describe(if (inner is TypeDecl.XRef) visited else visited + id)
    }

    /**
     * Resolve [id] and recurse into the referenced body, memoizing successful (non-back-edge) results in
     * [contentCache] — which is also what makes the result a shared DAG rather than an expanded tree.
     *
     * Mutually-recursive types: first computation wins, so where the back-edge falls depends on traversal
     * order. That is only safe because there is exactly one traversal and one cache. An earlier design
     * memoized a hash and a canonical string separately; the two visited in different orders, placed the
     * back-edge on different nodes, and disagreed about equality for cyclic types (`oaidl.h`'s
     * `_wireSAFEARRAY` ↔ `_wireSAFEARRAY_UNION`) — splitting one content class in two. Do not reintroduce
     * a second memo over this walk.
     */
    private fun refKey(id: GlobalTypeId, visited: Set<GlobalTypeId>): LayoutContent {
        if (id in visited) return LayoutContent()
        contentCache[id]?.let { return it }
        // Source-independent fallback for any unresolved id that slipped past the globalize-time Builtin
        // hoist: keyed on `n` alone, since the full GlobalTypeId carries `source` and would let per-CU
        // slots for the same logical builtin diverge.
        return byId(id)?.body?.describe(visited + id)?.also { contentCache[id] = it }
            ?: LayoutContent(GlobalTypeId::class.java, listOf(id.n))
    }

    /**
     * Deliberately not a `data class`: the generated `toString` walks the whole graph, and one of these
     * is reachable from every content diagnostic — printing them across a collection is what turned a
     * debug `println` into a 20-minute hang. Identity `toString` is useless but harmless; equality, which
     * is the entire point of the type, is spelled out below.
     */
    class LayoutContent(
        val klass: Class<*> = Nothing::class.java,
        val data: List<Any> = emptyList(),
        val children: List<List<LayoutContent>> = emptyList(),
    ) {
        // Both folded once, bottom-up. [refKey] hands the *same* instance to every referrer, so the graph
        // is a DAG and a naive walk re-visits each shared subgraph once per reference: on
        // crypto_mi_test_gcc421_fullstabs that is 16.0M visits against 154809 distinct nodes (~104x,
        // worst single node 11458). Safe to precompute: back-edges resolve to an empty LayoutContent, so
        // the graph is acyclic and children always exist before their parent.
        private val hash = Objects.hash(klass, data, children)

        /** Nodes a structural walk visits, sharing counted once per reference — so above the distinct
         *  node count. This is the cost of deep-walking (or stringifying) this node. */
        val expandedNodes: Int = 1 + children.sumOf { group -> group.sumOf { it.expandedNodes } }

        override fun hashCode() = hash

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            // Reject on the cached hash before descending: every deep comparison happens inside a
            // groupBy bucket, where unequal-but-same-bucket is exactly the case worth short-circuiting.
            if (other !is LayoutContent || hash != other.hash) return false
            return klass == other.klass && data == other.data && children == other.children
        }
    }

    private fun GlobalTypeDecl.layoutContent(visited: Set<GlobalTypeId>) = LayoutContent(
        javaClass,
        layoutData,
        children.map { field -> field.map { it.describe(visited) } },
    )

    private fun Field<GlobalTypeId>.layoutContent(visited: Set<GlobalTypeId>) = LayoutContent(
        javaClass,
        listOf(
            name,
            offsetBits,
            sizeBits,
            isStatic,
        ),
        listOf(listOf(type.describe(visited))),
    )

    // A virtual base's offset is the vtable's vbase slot with GNU extensions (`!1,12-96`) and the base's
    // position in the complete object with plain `-gstabs` (`basic_ios<…>:(0,114),64,…`): no layout of its own.
    private fun Base<GlobalTypeId>.layoutContent(visited: Set<GlobalTypeId>) = LayoutContent(
        javaClass,
        listOfNotNull(
            isVirtual,
            access,
            offsetBits.takeUnless { isVirtual },
        ),
        listOf(listOf(type.describe(visited))),
    )
}
