package ghistabs.harvest

import ghistabs.harvest.ContentHasher.Companion.BACK_EDGE_HASH
import ghistabs.materialize.ghidraClassName
import ghistabs.parse.*
import java.util.*

/**
 * Two-way oracle used by [contentHash]: id-keyed lookup for [TypeDecl.Ref], plus name+kind lookup
 * so a `XRef(STRUCT, "Foo")` resolves to the same struct content as a `Ref(id_of_Foo)`.
 */
abstract class ContentHasher(val hashCache: MutableMap<GlobalTypeId, Int> = mutableMapOf()) {
    // Method-dropped counterpart to [hashCache] for the [layoutHash] path — kept separate so its values
    // never poison the method-aware content hash. Memoizes so recursion stays linear on diamond graphs.
    private val layoutCache = mutableMapOf<GlobalTypeId, Int>()

    abstract fun byId(id: GlobalTypeId): TypeAst?
    abstract fun byXRef(xref: TypeDecl.XRef<GlobalTypeId>, silent: Boolean = false): TypeAst?

    /**
     * Content-equivalence hash for a [TypeDecl] tree.
     *
     * Differences from `data class hashCode()`:
     *  - Id-bearing nodes (`Ref`, `Range.of`, `Struct.vtableTargetTypeId`, `InlineDef.id`) resolve
     *    and hash by the referenced body, so `Ref(id)` and inline `InlineDef(id, body)`
     *    forms (gcc emits either depending on per-CU history) collapse to the same hash.
     *  - `"Ref"` and `"InlineDef"` wrapper tags are omitted — they reduce to their wrapped content.
     *
     * Cycles break via [visited]: a re-entry returns the fixed [BACK_EDGE_HASH].
     * [hashCache] memoizes successful (non-back-edge) results.
     */
    fun contentHash(
        decl: TypeDecl<GlobalTypeId>,
        visited: Set<GlobalTypeId> = emptySet(),
        layoutOnly: Boolean = false,
    ): Int = decl.run {
        when (this) {
            TypeDecl.Void -> Objects.hash("Void")

            is TypeDecl.Ref -> refKey(id, visited, layoutOnly)

            // Normalize primitives to the Ghidra type they materialize to (see BuiltinTable.canonicalKey),
            // so char's `Range(0,127)` / `WithSizeAttr(8, …)` / `Builtin(-2)` spellings share one hash and
            // don't fork a `.conflict`. Non-primitive shapes fall through to their structural hash.
            is TypeDecl.Range -> builtinHash() ?: Objects.hash("Range", refKey(of, visited, layoutOnly), min, max)

            // gcc's `r<base>;<size>;0;` has `<base>` purely decorative (varies per CU). Hash by size only.
            is TypeDecl.Float -> Objects.hash("Float", sizeBytes)

            is TypeDecl.Pointer -> Objects.hash("Pointer", contentHash(pointee, visited, layoutOnly))

            is TypeDecl.Reference -> Objects.hash("Reference", contentHash(referent, visited, layoutOnly))

            is TypeDecl.Const -> Objects.hash("Const", contentHash(inner, visited, layoutOnly))

            is TypeDecl.Volatile -> Objects.hash("Volatile", contentHash(inner, visited, layoutOnly))

            is TypeDecl.Array -> Objects.hash(
                "Array",
                contentHash(element, visited, layoutOnly),
                length,
                indexType?.hash(visited, layoutOnly),
            )

            is TypeDecl.Enum -> hashCode()

            // members: List<Pair<String, Long>> — no ids

            // The DTM struct has no static members or methods, and both are cycle sources (libstdc++
            // `basic_string ↔ _Rep` recurse through static `_S_empty_rep_storage` and method signatures) —
            // hashing them makes the traversal-order BACK_EDGE land on different nodes per CU, forking
            // `.conflict` on layout-identical types. Static fields are always dropped; methods are dropped
            // under [layoutOnly] (recursively — bases carry the same per-CU virt/order noise), else hashed
            // by mangled name ([MethodDecl.contentHash]).
            is TypeDecl.Struct -> Objects.hash(
                "Struct",
                rawKind,
                sizeBytes,
                bases.map { it.hash(visited, layoutOnly) },
                fields.filter { !it.isStatic }.map { it.hash(visited, layoutOnly) },
                if (layoutOnly) emptyList<Int>() else methods.map { it.contentHash() },
                hasVTablePointerMarker,
                vtableTargetTypeId?.let { refKey(it, visited, layoutOnly) },
            )

            is TypeDecl.FunctionT -> Objects.hash(
                "FunctionT",
                ret.hash(visited, layoutOnly),
                params.map { it.hash(visited, layoutOnly) },
            )

            is TypeDecl.Method -> Objects.hash(
                "Method",
                cls.hash(visited, layoutOnly),
                ret.hash(visited, layoutOnly),
                params.map { it.hash(visited, layoutOnly) },
            )

            is TypeDecl.Complex -> hashCode()

            // Resolve XRef to its struct definition so a forward-declaration-only CU hashes any
            // surrounding type identically to a full-definition CU. Falls back to (kind, tagName)
            // when truly unresolved.
            is TypeDecl.XRef ->
                byXRef(this, silent = true)?.id?.let { refKey(it, visited, layoutOnly) } ?: hashCode()

            // Source-independent: same slot in every CU = same primitive.
            is TypeDecl.Builtin -> builtinHash() ?: Objects.hash("Builtin", slot)

            is TypeDecl.WithSizeAttr -> builtinHash() ?: Objects.hash(
                "WithSizeAttr",
                sizeBits,
                inner.hash(visited, layoutOnly),
            )

            // Skip the visited guard when body is an XRef: byXRef resolution must still be able to
            // add the resolved id to `visited` naturally. Without this, the pattern
            //   InlineDef(id=B, body=XRef(STRUCT, Foo))   resolving to id=B's own Struct
            // would pre-mark B and make refKey(B) return BACK_EDGE_HASH instead of struct content.
            // For non-XRef bodies the guard IS required (a Ref(id) in a Struct body must not recurse).
            is TypeDecl.InlineDef -> body.hash(if (body is TypeDecl.XRef) visited else visited + id, layoutOnly)
        }
    }

    /**
     * Layout-only hash — [contentHash] with every struct's methods dropped, recursively. gcc emits a
     * virtual as VIRTUAL (vtoff set) in its defining CU and NORMAL (vtoff null) elsewhere, and reorders
     * methods per CU, so a layout-identical class hashes differently across CUs — and the divergence
     * propagates through method-bearing bases (`basic_istream : virtual basic_ios`). Group scope owners
     * by this so per-CU method noise doesn't falsely demote a scope group to header keys.
     */
    fun layoutHash(body: TypeDecl<GlobalTypeId>): Int = contentHash(body, layoutOnly = true)

    /**
     * Resolve [id] and recurse into the referenced body. Memoizes successful (non-back-edge) results in
     * [hashCache] for [contentHash], in [layoutCache] for [layoutHash] (`layoutOnly`). Mutually-recursive
     * types: first computation wins — deterministic across calls; good enough for collision detection.
     */
    fun refKey(id: GlobalTypeId, visited: Set<GlobalTypeId>, layoutOnly: Boolean = false): Int {
        if (id in visited) return Objects.hash("back-edge")
        val cache = if (layoutOnly) layoutCache else hashCache
        cache[id]?.let { return it }
        // Source-independent fallback for any unresolved id that slipped past the globalize-time
        // Builtin hoist. Hashing the full GlobalTypeId would bake `source` in and let per-CU
        // slots for the same logical builtin diverge.
        val referenced = byId(id) ?: return Objects.hash("unresolved", id.n)
        return contentHash(referenced.body, visited + id, layoutOnly).also { cache[id] = it }
    }

    private fun TypeDecl<GlobalTypeId>.hash(visited: Set<GlobalTypeId> = emptySet(), layoutOnly: Boolean = false) =
        contentHash(this, visited, layoutOnly)

    private fun FieldDecl<GlobalTypeId>.hash(visited: Set<GlobalTypeId>, layoutOnly: Boolean) = Objects.hash(
        "Field",
        name,
        contentHash(type, visited, layoutOnly),
        offsetBits,
        sizeBits,
        isStatic,
    )

    private fun BaseDecl<GlobalTypeId>.hash(visited: Set<GlobalTypeId>, layoutOnly: Boolean) =
        Objects.hash("Base", contentHash(type, visited, layoutOnly), isVirtual, access, offsetBits)

    companion object {
        // Class-name key is stable across CUs and equal for every stab spelling of the same primitive.
        private fun TypeDecl<GlobalTypeId>.builtinHash(): Int? = ghidraClassName()?.hashCode()

        private val BACK_EDGE_HASH = Objects.hash("back-edge")

        private fun MethodDecl<GlobalTypeId>.contentHash() = Objects.hash(
            "Method",
            name,
            // The mangled name already encodes the full signature, so hashing it identifies the method
            // without recursing into return/param types — which, for a method referencing its own class
            // (basic_string↔_Rep), would re-enter the type graph and make the hash order-dependent.
            mangled,
            access,
            virt,
            isConst,
            isVolatile,
            vtableOffsetBits,
        )
    }
}

internal fun TypeDecl<GlobalTypeId>.contentHash(oracle: ContentHasher, visited: Set<GlobalTypeId> = emptySet()): Int =
    oracle.contentHash(this, visited)
