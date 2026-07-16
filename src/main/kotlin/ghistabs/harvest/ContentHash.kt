package ghistabs.harvest

import ghistabs.materialize.BuiltinTable
import ghistabs.parse.*
import java.util.*

/**
 * Two-way oracle used by [contentHash]: id-keyed lookup for [TypeDecl.Ref], plus name+kind lookup
 * so a `XRef(STRUCT, "Foo")` resolves to the same struct content as a `Ref(id_of_Foo)`.
 */
interface TypeAstOracle {
    fun byId(id: GlobalTypeId): TypeAst?
    fun byXRef(xref: TypeDecl.XRef<GlobalTypeId>): TypeAst? = null

    companion object {
        /** Lambda-form constructor for tests. */
        operator fun invoke(
            byId: (GlobalTypeId) -> TypeAst?,
            byXRef: (TypeDecl.XRef<GlobalTypeId>) -> TypeAst? = { _ -> null },
        ): TypeAstOracle = object : TypeAstOracle {
            override fun byId(id: GlobalTypeId) = byId(id)
            override fun byXRef(xref: TypeDecl.XRef<GlobalTypeId>) = byXRef(xref)
        }
    }
}

/**
 * Content-equivalence hash for a [TypeDecl] tree.
 *
 * Differences from `data class hashCode()`:
 *  - Id-bearing nodes (`Ref`, `Range.of`, `Struct.vtableTargetTypeId`, `InlineDef.id`) resolve
 *    through [oracle] and hash by the referenced body, so `Ref(id)` and inline `InlineDef(id, body)`
 *    forms (gcc emits either depending on per-CU history) collapse to the same hash.
 *  - `"Ref"` and `"InlineDef"` wrapper tags are omitted — they reduce to their wrapped content.
 *
 * Cycles break via [visited]: a re-entry returns the fixed [BACK_EDGE_HASH].
 * [cache] memoizes successful (non-back-edge) results.
 */
fun TypeDecl<GlobalTypeId>.contentHash(
    oracle: TypeAstOracle,
    cache: MutableMap<GlobalTypeId, Int>? = null,
    visited: Set<GlobalTypeId> = emptySet(),
): Int = when (this) {
    is TypeDecl.Ref -> id.refKey(oracle, cache, visited)

    // Normalize primitives to the Ghidra type they materialize to (see BuiltinTable.canonicalKey),
    // so char's `Range(0,127)` / `WithSizeAttr(8, …)` / `Builtin(-2)` spellings share one hash and
    // don't fork a `.conflict`. Non-primitive shapes fall through to their structural hash.
    is TypeDecl.Range -> builtinHash() ?: Objects.hash("Range", of.refKey(oracle, cache, visited), min, max)

    // gcc's `r<base>;<size>;0;` has `<base>` purely decorative (varies per CU). Hash by size only.
    is TypeDecl.Float -> Objects.hash("Float", sizeBytes)

    is TypeDecl.Pointer -> Objects.hash("Pointer", pointee.contentHash(oracle, cache, visited))

    is TypeDecl.Reference -> Objects.hash("Reference", referent.contentHash(oracle, cache, visited))

    is TypeDecl.Const -> Objects.hash("Const", inner.contentHash(oracle, cache, visited))

    is TypeDecl.Volatile -> Objects.hash("Volatile", inner.contentHash(oracle, cache, visited))

    is TypeDecl.Array -> Objects.hash(
        "Array",
        element.contentHash(oracle, cache, visited),
        length,
        indexType?.contentHash(oracle, cache, visited),
    )

    is TypeDecl.Enum -> hashCode()

    // members: List<Pair<String, Long>> — no ids

    // Layout-only equivalence: the DTM struct has no static members or methods, and both are
    // cycle sources (libstdc++ `basic_string ↔ _Rep` recurse through static `_S_empty_rep_storage`
    // and method signatures). Hashing them makes the traversal-order-dependent BACK_EDGE land on
    // different nodes per CU, forking `.conflict` on layout-identical types. Static fields are
    // dropped here; methods are hashed by mangled name only (see MethodDecl.contentHash).
    is TypeDecl.Struct -> Objects.hash(
        "Struct",
        rawKind,
        sizeBytes,
        bases.map { it.contentHash(oracle, cache, visited) },
        fields.filter { !it.isStatic }.map { it.contentHash(oracle, cache, visited) },
        methods.map { it.contentHash(oracle, cache, visited) },
        hasVTablePointerMarker,
        vtableTargetTypeId?.refKey(oracle, cache, visited),
    )

    is TypeDecl.FunctionT -> Objects.hash(
        "FunctionT",
        ret.contentHash(oracle, cache, visited),
        params.map { it.contentHash(oracle, cache, visited) },
    )

    is TypeDecl.Method -> Objects.hash(
        "Method",
        cls.contentHash(oracle, cache, visited),
        ret.contentHash(oracle, cache, visited),
        params.map { it.contentHash(oracle, cache, visited) },
    )

    is TypeDecl.Complex -> hashCode()

    // Resolve XRef to its struct definition so a forward-declaration-only CU hashes any
    // surrounding type identically to a full-definition CU. Falls back to (kind, tagName)
    // when truly unresolved.
    is TypeDecl.XRef -> oracle.byXRef(this)?.id?.refKey(oracle, cache, visited) ?: hashCode()

    // Source-independent: same slot in every CU = same primitive.
    is TypeDecl.Builtin -> builtinHash() ?: Objects.hash("Builtin", slot)

    is TypeDecl.WithSizeAttr -> builtinHash() ?: Objects.hash(
        "WithSizeAttr",
        sizeBits,
        inner.contentHash(oracle, cache, visited),
    )

    // Skip the visited guard when body is an XRef: byXRef resolution must still be able to
    // add the resolved id to `visited` naturally. Without this, the pattern
    //   InlineDef(id=B, body=XRef(STRUCT, Foo))   resolving to id=B's own Struct
    // would pre-mark B and make refKey(B) return BACK_EDGE_HASH instead of struct content.
    // For non-XRef bodies the guard IS required (a Ref(id) in a Struct body must not recurse).
    is TypeDecl.InlineDef -> body.contentHash(oracle, cache, if (body is TypeDecl.XRef) visited else visited + id)
}

/**
 * Resolve [this] through [oracle] and recurse into the referenced body. Memoizes successful
 * (non-back-edge) results in [cache]. For mutually-recursive types the first computation wins —
 * deterministic across calls; good enough for collision detection and DTM dedup.
 */
private fun GlobalTypeId.refKey(
    oracle: TypeAstOracle,
    cache: MutableMap<GlobalTypeId, Int>?,
    visited: Set<GlobalTypeId>,
): Int {
    if (this in visited) return BACK_EDGE_HASH
    cache?.get(this)?.let { return it }
    // Source-independent fallback for any unresolved id that slipped past the globalize-time
    // Builtin hoist. Hashing the full GlobalTypeId would bake `source` in and let per-CU
    // slots for the same logical builtin diverge.
    val referenced = oracle.byId(this) ?: return Objects.hash("unresolved", n)
    val h = referenced.body.contentHash(oracle, cache, visited + this)
    cache?.put(this, h)
    return h
}

// Class-name key is stable across CUs and equal for every stab spelling of the same primitive.
private fun TypeDecl<GlobalTypeId>.builtinHash(): Int? = BuiltinTable.canonicalKey(this)?.hashCode()

private val BACK_EDGE_HASH = Objects.hash("back-edge")

private fun FieldDecl<GlobalTypeId>.contentHash(
    oracle: TypeAstOracle,
    cache: MutableMap<GlobalTypeId, Int>?,
    visited: Set<GlobalTypeId>,
) = Objects.hash(
    "Field",
    name,
    type.contentHash(oracle, cache, visited),
    offsetBits,
    sizeBits,
    isStatic,
)

private fun BaseDecl<GlobalTypeId>.contentHash(
    oracle: TypeAstOracle,
    cache: MutableMap<GlobalTypeId, Int>?,
    visited: Set<GlobalTypeId>,
) = Objects.hash("Base", type.contentHash(oracle, cache, visited), isVirtual, access, offsetBits)

private fun MethodDecl<GlobalTypeId>.contentHash(
    oracle: TypeAstOracle,
    cache: MutableMap<GlobalTypeId, Int>?,
    visited: Set<GlobalTypeId>,
) = Objects.hash(
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
