package ghistabs.harvest

import ghistabs.diagnose.DiagnosticSink
import ghistabs.materialize.ghidraClassName
import ghistabs.parse.*
import java.util.*

/**
 * Two-way oracle used by [contentHash]: id-keyed lookup for [TypeDecl.Ref], plus name+kind lookup
 * so a `XRef(STRUCT, "Foo")` resolves to the same struct content as a `Ref(id_of_Foo)`. Is a
 * [DiagnosticSink] so [groupByContent] can report hash collisions where it detects them.
 */
abstract class ContentHasher(val hashCache: MutableMap<GlobalTypeId, Int> = mutableMapOf()) : DiagnosticSink {
    abstract fun byId(id: GlobalTypeId): TypeAst?
    abstract fun byXRef(xref: TypeDecl.XRef<GlobalTypeId>, silent: Boolean = false): TypeAst?

    /**
     * Layout-equivalence hash for a [TypeDecl] tree.
     *
     * Differences from `data class hashCode()`:
     *  - Id-bearing nodes (`Ref`, `Range.of`, `Struct.vtableTargetTypeId`, `InlineDef.id`) resolve
     *    and hash by the referenced body, so `Ref(id)` and inline `InlineDef(id, body)`
     *    forms (gcc emits either depending on per-CU history) collapse to the same hash.
     *  - `"Ref"` and `"InlineDef"` wrapper tags are omitted — they reduce to their wrapped content.
     *  - Struct methods and static fields are dropped (see the Struct branch), so layout-identical
     *    classes hash equal across CUs regardless of per-CU method virt/order noise.
     *
     * Cycles break via [visited]: a re-entry returns the fixed back-edge hash. [hashCache] memoizes
     * successful (non-back-edge) results.
     */
    fun contentHash(decl: TypeDecl<GlobalTypeId>, visited: Set<GlobalTypeId> = emptySet()): Int = decl.run {
        when (this) {
            TypeDecl.Void -> Objects.hash("Void")

            is TypeDecl.Ref -> refKey(id, visited)

            // Normalize primitives to the Ghidra type they materialize to (see BuiltinTable.canonicalKey),
            // so char's `Range(0,127)` / `WithSizeAttr(8, …)` / `Builtin(-2)` spellings share one hash and
            // don't fork a `.conflict`. Non-primitive shapes fall through to their structural hash.
            is TypeDecl.Range -> builtinHash() ?: Objects.hash("Range", refKey(of, visited), min, max)

            // gcc's `r<base>;<size>;0;` has `<base>` purely decorative (varies per CU). Hash by size only.
            is TypeDecl.Float -> Objects.hash("Float", sizeBytes)

            is TypeDecl.Pointer -> Objects.hash("Pointer", contentHash(pointee, visited))

            is TypeDecl.Reference -> Objects.hash("Reference", contentHash(referent, visited))

            is TypeDecl.Const -> Objects.hash("Const", contentHash(inner, visited))

            is TypeDecl.Volatile -> Objects.hash("Volatile", contentHash(inner, visited))

            is TypeDecl.Array -> Objects.hash("Array", contentHash(element, visited), length, indexType?.hash(visited))

            is TypeDecl.Enum -> hashCode()

            // members: List<Pair<String, Long>> — no ids

            // The DTM struct has no static members or methods, and both are cycle sources (libstdc++
            // `basic_string ↔ _Rep` recurse through static `_S_empty_rep_storage` and method signatures) —
            // hashing them makes the traversal-order BACK_EDGE land on different nodes per CU, forking
            // `.conflict` on layout-identical types. gcc also emits a virtual as VIRTUAL (vtoff set) in its
            // defining CU and NORMAL elsewhere, reordering methods per CU. So static fields and methods are
            // dropped: a layout-identical class hashes equal everywhere.
            is TypeDecl.Struct -> Objects.hash(
                "Struct",
                rawKind,
                sizeBytes,
                bases.map { it.hash(visited) },
                fields.filter { !it.isStatic }.map { it.hash(visited) },
                hasVTablePointerMarker,
                vtableTargetTypeId?.let { refKey(it, visited) },
            )

            is TypeDecl.FunctionT -> Objects.hash("FunctionT", ret.hash(visited), params.map { it.hash(visited) })

            is TypeDecl.Method -> Objects.hash(
                "Method",
                cls.hash(visited),
                ret.hash(visited),
                params.map { it.hash(visited) },
            )

            is TypeDecl.Complex -> hashCode()

            // Resolve XRef to its struct definition so a forward-declaration-only CU hashes any
            // surrounding type identically to a full-definition CU. Falls back to (kind, tagName)
            // when truly unresolved.
            is TypeDecl.XRef -> byXRef(this, silent = true)?.id?.let { refKey(it, visited) } ?: hashCode()

            // Source-independent: same slot in every CU = same primitive.
            is TypeDecl.Builtin -> builtinHash() ?: Objects.hash("Builtin", slot)

            is TypeDecl.WithSizeAttr -> builtinHash() ?: Objects.hash("WithSizeAttr", sizeBits, inner.hash(visited))

            // Skip the visited guard when body is an XRef: byXRef resolution must still be able to
            // add the resolved id to `visited` naturally. Without this, the pattern
            //   InlineDef(id=B, body=XRef(STRUCT, Foo))   resolving to id=B's own Struct
            // would pre-mark B and make refKey(B) return BACK_EDGE_HASH instead of struct content.
            // For non-XRef bodies the guard IS required (a Ref(id) in a Struct body must not recurse).
            is TypeDecl.InlineDef -> body.hash(if (body is TypeDecl.XRef) visited else visited + id)
        }
    }

    /**
     * Resolve [id] and recurse into the referenced body, memoizing successful (non-back-edge) results in
     * [hashCache]. Mutually-recursive types: first computation wins — deterministic across calls; good
     * enough for collision detection.
     */
    fun refKey(id: GlobalTypeId, visited: Set<GlobalTypeId>): Int {
        if (id in visited) return Objects.hash("back-edge")
        hashCache[id]?.let { return it }
        // Source-independent fallback for any unresolved id that slipped past the globalize-time
        // Builtin hoist. Hashing the full GlobalTypeId would bake `source` in and let per-CU
        // slots for the same logical builtin diverge.
        val referenced = byId(id) ?: return Objects.hash("unresolved", id.n)
        return contentHash(referenced.body, visited + id).also { hashCache[id] = it }
    }

    /**
     * Partition [items] into content-equivalence classes. Bucket by [contentHash] (fast), then split
     * each bucket by [contentEq] — a 32-bit hash *collision* must never merge two distinct-content
     * types, so grouping decisions (§A/§B) go through here, not raw `groupBy { contentHash }`.
     */
    fun <T> groupByContent(items: Iterable<T>, bodyOf: (T) -> TypeDecl<GlobalTypeId>): List<List<T>> =
        items.groupBy { contentHash(bodyOf(it)) }.values.flatMap { bucket ->
            // Size-1 buckets (the common case for a decent hash) never build a string. Multi-item
            // buckets are hash collisions: split by the exact canonical string, O(bucket) not O(bucket²).
            if (bucket.size == 1) {
                listOf(bucket)
            } else {
                val classes = bucket.groupBy { describe(bodyOf(it), emptySet()) }
                // A bucket splitting into >1 class means contentHash collided across distinct content —
                // contentEq caught what `groupBy { contentHash }` would have wrongly merged. Log the
                // colliding forms (debug both counts and logs; 0 on the corpus keeps the counter absent).
                if (classes.size > 1) debug("contenthash-collision", classes.keys.joinToString(" ⟂ ") { it.take(80) })
                classes.values
            }
        }

    /**
     * Exact structural layout-equality — [describe]'s canonical string mirrors [contentHash]'s inputs
     * (same fields, ref resolution, back-edge, dropped methods/static), so equal content ⇒ equal hash
     * (buckets never split a real class) while string equality is collision-free (buckets never merge).
     */
    fun contentEq(a: TypeDecl<GlobalTypeId>, b: TypeDecl<GlobalTypeId>): Boolean =
        describe(a, emptySet()) == describe(b, emptySet())

    private val describeCache = mutableMapOf<GlobalTypeId, String>()

    private fun describe(decl: TypeDecl<GlobalTypeId>, visited: Set<GlobalTypeId>): String = decl.run {
        when (this) {
            TypeDecl.Void -> "void"
            is TypeDecl.Ref -> refStr(id, visited)
            is TypeDecl.Range -> ghidraClassName() ?: "r(${refStr(of, visited)};$min;$max)"
            is TypeDecl.Float -> "f$sizeBytes"
            is TypeDecl.Pointer -> "*${describe(pointee, visited)}"
            is TypeDecl.Reference -> "&${describe(referent, visited)}"
            is TypeDecl.Const -> "k${describe(inner, visited)}"
            is TypeDecl.Volatile -> "V${describe(inner, visited)}"
            is TypeDecl.Array -> "arr[${describe(element, visited)};$length;${indexType?.let {
                describe(it, visited)
            }}]"
            is TypeDecl.Enum -> "enum$members"
            is TypeDecl.Struct ->
                "s{$rawKind;$sizeBytes;" +
                    bases.joinToString(",", "[", "]") {
                        "B${describe(it.type, visited)};${it.isVirtual};${it.access};${it.offsetBits}"
                    } +
                    fields.filter { !it.isStatic }.joinToString(",", "[", "]") {
                        "${it.name}:${describe(it.type, visited)}@${it.offsetBits}/${it.sizeBits}"
                    } +
                    ";$hasVTablePointerMarker;${vtableTargetTypeId?.let { refStr(it, visited) }}}"
            is TypeDecl.FunctionT -> "F(${describe(ret, visited)};${params.joinToString(",") {
                describe(it, visited)
            }})"
            is TypeDecl.Method ->
                "M(${describe(cls, visited)};${describe(ret, visited)};${params.joinToString(",") {
                    describe(it, visited)
                }})"
            is TypeDecl.Complex -> "cx$rCode;$sizeBytes"
            is TypeDecl.XRef -> byXRef(this, silent = true)?.id?.let { refStr(it, visited) } ?: "x$kind$tagName"
            is TypeDecl.Builtin -> ghidraClassName() ?: "b$slot"
            is TypeDecl.WithSizeAttr -> ghidraClassName() ?: "w$sizeBits;${describe(inner, visited)}"
            is TypeDecl.InlineDef -> describe(body, if (body is TypeDecl.XRef) visited else visited + id)
        }
    }

    private fun refStr(id: GlobalTypeId, visited: Set<GlobalTypeId>): String {
        if (id in visited) return "@"
        describeCache[id]?.let { return it }
        return byId(id)?.let { describe(it.body, visited + id) }?.also { describeCache[id] = it } ?: "?${id.n}"
    }

    private fun TypeDecl<GlobalTypeId>.hash(visited: Set<GlobalTypeId> = emptySet()) = contentHash(this, visited)

    private fun FieldDecl<GlobalTypeId>.hash(visited: Set<GlobalTypeId>) = Objects.hash(
        "Field",
        name,
        contentHash(type, visited),
        offsetBits,
        sizeBits,
        isStatic,
    )

    private fun BaseDecl<GlobalTypeId>.hash(visited: Set<GlobalTypeId>) =
        Objects.hash("Base", contentHash(type, visited), isVirtual, access, offsetBits)

    companion object {
        // Class-name key is stable across CUs and equal for every stab spelling of the same primitive.
        private fun TypeDecl<GlobalTypeId>.builtinHash(): Int? = ghidraClassName()?.hashCode()
    }
}

internal fun TypeDecl<GlobalTypeId>.contentHash(oracle: ContentHasher, visited: Set<GlobalTypeId> = emptySet()): Int =
    oracle.contentHash(this, visited)
