package ghistabs.index

import ghistabs.diagnose.DiagnosticSink
import ghistabs.harvest.Type
import ghistabs.materialize.ghidraClass
import ghistabs.parse.GlobalTypeDecl
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl
import ghistabs.parse.TypeDecl.Aggregate.Base
import ghistabs.parse.TypeDecl.Aggregate.Field
import java.util.*

/**
 * Two-way oracle used by [content]: id-keyed lookup for [TypeDecl.Ref], plus name+kind lookup so a
 * `XRef(STRUCT, "Foo")` resolves to the same struct content as a `Ref(id_of_Foo)`. Is a
 * [DiagnosticSink] so resolution failures are reported where they are detected.
 */
abstract class ContentIndex(val contentCache: MutableMap<GlobalTypeId, LayoutContent> = mutableMapOf()) :
    DiagnosticSink {
    abstract fun byId(id: GlobalTypeId): Type?
    abstract fun byXRef(xref: TypeDecl.XRef<GlobalTypeId>, silent: Boolean = false): Type?

    /**
     * Canonical layout of a [TypeDecl] tree, as a value: equal [LayoutContent] ⇔ layout-equivalent
     * types. One traversal serves both grouping and equality, so the two cannot drift apart.
     *
     * Differences from `data class equals()` on the TypeDecl itself:
     *  - Id-bearing nodes (`Ref`, `Struct.vptrBasetype`, `InlineDef.id`) resolve to the referenced
     *    body, so `Ref(id)` and inline `InlineDef(id, body)` forms (gcc emits either depending on
     *    per-CU history) collapse to the same content.
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

        TypeDecl.Void, is TypeDecl.Float, is TypeDecl.Complex, is TypeDecl.Enum, // no children
        is TypeDecl.Pointer, is TypeDecl.Reference, is TypeDecl.Const, is TypeDecl.Volatile, // one child
        is TypeDecl.Array, is TypeDecl.FreeFunction, // two children
        is TypeDecl.Method, // three children
        -> layoutContent(visited)

        // Source-independent: same slot in every CU = same primitive. Reduce to the Ghidra type the
        // stab materializes to (see [ghidraClassName]), so char's `Range(0,127)` / `WithSizeAttr(8, …)` /
        // `Builtin(-2)` spellings are one value and don't fork a `.conflict`. A shape that maps to no
        // primitive falls through to its structural content.
        is TypeDecl.Builtin, is TypeDecl.Range, is TypeDecl.WithSizeAttr ->
            ghidraClass()?.let { LayoutContent(it) } ?: layoutContent(visited)

        // The DTM struct has no static members or methods, and both are cycle sources (libstdc++
        // `basic_string ↔ _Rep` recurse through static `_S_empty_rep_storage` and method signatures) —
        // including them makes the traversal-order back-edge land on different nodes per CU, forking
        // `.conflict` on layout-identical types. gcc also emits a virtual as VIRTUAL (vtoff set) in its
        // defining CU and NORMAL elsewhere, reordering methods per CU. So static fields and methods are
        // dropped: a layout-identical class is one value everywhere.
        is TypeDecl.Aggregate -> LayoutContent(
            javaClass,
            layoutData,
            listOf(
                bases.map { it.layoutContent(visited) },
                fields.filter { !it.isStatic }.map { it.layoutContent(visited) },
                listOfNotNull(vptrBasetype?.describe(visited)),
            ),
        )

        // Resolve XRef to its struct definition so a forward-declaration-only CU yields the same content
        // for any surrounding type as a full-definition CU. Falls back to (kind, tagName) — its own
        // layoutData — when truly unresolved.
        is TypeDecl.XRef -> byXRef(this, silent = true)?.id?.let { refKey(it, visited) } ?: layoutContent(visited)

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

    private fun Base<GlobalTypeId>.layoutContent(visited: Set<GlobalTypeId>) = LayoutContent(
        javaClass,
        listOf(
            isVirtual,
            access,
            offsetBits,
        ),
        listOf(listOf(type.describe(visited))),
    )
}
