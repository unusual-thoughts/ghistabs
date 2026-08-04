package ghistabs.harvest

import ghistabs.diagnose.DiagnosticSink
import ghistabs.materialize.ghidraClassName
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl
import ghistabs.parse.TypeDecl.Struct.Base
import ghistabs.parse.TypeDecl.Struct.Field
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
    fun content(decl: TypeDecl<GlobalTypeId>, visited: Set<GlobalTypeId> = emptySet()) = decl.describe(visited)

    private fun TypeDecl<GlobalTypeId>.describe(visited: Set<GlobalTypeId> = emptySet()): LayoutContent = when (this) {
        is TypeDecl.Ref -> refKey(id, visited)

        TypeDecl.Void, is TypeDecl.Float, is TypeDecl.Complex, is TypeDecl.Enum, // no children
        is TypeDecl.Pointer, is TypeDecl.Reference, is TypeDecl.Const, is TypeDecl.Volatile, // one child
        is TypeDecl.Array, is TypeDecl.FunctionT, // two children
        is TypeDecl.Method, // three children
        -> layoutContent(visited)

        // Source-independent: same slot in every CU = same primitive. Reduce to the Ghidra type the
        // stab materializes to (see [ghidraClassName]), so char's `Range(0,127)` / `WithSizeAttr(8, …)` /
        // `Builtin(-2)` spellings are one value and don't fork a `.conflict`. A shape that maps to no
        // primitive falls through to its structural content.
        is TypeDecl.Builtin, is TypeDecl.Range, is TypeDecl.WithSizeAttr ->
            ghidraClassName()?.let { LayoutContent(it) } ?: layoutContent(visited)

        // The DTM struct has no static members or methods, and both are cycle sources (libstdc++
        // `basic_string ↔ _Rep` recurse through static `_S_empty_rep_storage` and method signatures) —
        // including them makes the traversal-order back-edge land on different nodes per CU, forking
        // `.conflict` on layout-identical types. gcc also emits a virtual as VIRTUAL (vtoff set) in its
        // defining CU and NORMAL elsewhere, reordering methods per CU. So static fields and methods are
        // dropped: a layout-identical class is one value everywhere.
        is TypeDecl.Struct -> LayoutContent(
            this.javaClass,
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
        is TypeDecl.InlineDef -> body.describe(if (body is TypeDecl.XRef) visited else visited + id)
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

    data class LayoutContent(
        val klass: Class<*> = Nothing::class.java,
        val data: List<Any> = emptyList(),
        val children: List<List<LayoutContent>> = emptyList(),
    ) {
        // Computed once, bottom-up: [refKey] hands the *same* instance to every referrer, so the graph
        // is a DAG and the generated hashCode would re-walk a shared subgraph once per reference —
        // exponential in sharing depth on libstdc++ templates. Each node folds its children's cached
        // hashes instead, making the whole traversal O(edges). Safe to precompute: back-edges resolve
        // to an empty LayoutContent, so the graph is acyclic and children exist before their parent.
        private val hash = Objects.hash(klass, data, children)

        override fun hashCode() = hash
    }

    private fun TypeDecl<GlobalTypeId>.layoutContent(visited: Set<GlobalTypeId>) = LayoutContent(
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
