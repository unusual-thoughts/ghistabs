package ghistabs.harvest

import ghistabs.parse.*
import java.util.*

/**
 * Two-way oracle used by [contentHash]: an id-keyed lookup for [ghistabs.parse.TypeDecl.Ref]
 * resolution and a name+kind lookup so [ghistabs.parse.TypeDecl.XRef] can resolve to the
 * struct it forward-declares.
 *
 * The XRef path is what lets a CU that only saw `struct Foo;` and one that
 * saw the full definition produce the same content hash for any type built
 * around `Foo` — without it, `XRef(STRUCT, "Foo")` and `Ref(id_of_Foo)`
 * hash to completely different values.
 */
class TypeAstOracle(
    val byId: (GlobalTypeId) -> TypeAst?,
    val byXRef: (TypeDecl.XRef<GlobalTypeId>) -> TypeAst? = { _ -> null },
) {
    companion object {
        /** Adapter for legacy callers (tests) that only need id-based lookups. */
        operator fun invoke(byId: (GlobalTypeId) -> TypeAst?): TypeAstOracle = TypeAstOracle(byId, { _ -> null })
    }
}

/**
 * Content-equivalence hash for a [TypeDecl] tree. Differs from the
 * default `data class` `hashCode()` in two places:
 *
 *   1. Anywhere a [TypeDecl] holds an id (`Ref`, `Range.of`,
 *      `Struct.vtableTargetTypeId`, `InlineDef.id`), the id is resolved
 *      via [oracle] and the hash recurses into the referenced body —
 *      so a forward `Ref(id)` and an inline `InlineDef(id, body)` for
 *      the same content collapse to the same hash. gcc emits either
 *      form depending on per-CU history.
 *
 *   2. The `"Ref"` and `"InlineDef"` wrapper tags are intentionally
 *      omitted — both reduce to their wrapped content's hash. Per-CU
 *      template-instantiation clones end up content-equivalent because
 *      their fields' refs converge on the same primitive types
 *      regardless of which CU canonically owns the clone.
 *
 * Cycles (self-referential `Range.of`, recursive struct fields, vtable
 * pointing back at the enclosing class) are broken by [cache]: once
 * a [GlobalTypeId] is in flight, hitting it again yields a fixed
 * `"back-edge"` marker hash instead of recursing.
 *
 * [oracle] is parameterised so `Harvester.appendAsts` can compose its
 * in-flight batch with the merged store, while a finished [Harvest]
 * can pass `typeAsts::get` directly.
 *
 * Each `when` branch destructures the variant — adding a field to any
 * [TypeDecl] subclass is a compile error here.
 */
fun TypeDecl<GlobalTypeId>.contentHash(
    oracle: TypeAstOracle,
    cache: MutableMap<GlobalTypeId, Int>? = null,
    visited: Set<GlobalTypeId> = emptySet(),
): Int = when (this) {
    // Drop the "Ref" wrapper so `Ref(id)` and the equivalent inline
    // `InlineDef(id, content)` (gcc emits either form depending on
    // each CU's history) reduce to the same content hash.
    is TypeDecl.Ref -> id.refKey(oracle, cache, visited)

    is TypeDecl.Range -> Objects.hash("Range", of.refKey(oracle, cache, visited), min, max)

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
    is TypeDecl.Struct -> Objects.hash(
        "Struct",
        kind,
        sizeBytes,
        bases.map { it.contentHash(oracle, cache, visited) },
        fields.map { it.contentHash(oracle, cache, visited) },
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

    // Resolve `XRef(kind, name)` to the canonical struct definition so a
    // CU that only saw the forward-declaration `struct Foo;` hashes any
    // surrounding type the same way as a CU that saw the full body. Falls
    // back to the plain (kind, tagName) hash when no struct with that
    // name exists yet (truly unresolved forward decl).
    is TypeDecl.XRef -> oracle.byXRef(this)?.id?.refKey(oracle, cache, visited) ?: hashCode()

    // gcc XCOFF builtin slot: hash by slot number alone (source-independent).
    // Same negative slot in every CU = same primitive = same hash.
    is TypeDecl.Builtin -> Objects.hash("Builtin", slot)

    // (kind, tagName) — primitives only
    is TypeDecl.WithSizeAttr -> Objects.hash(
        "WithSizeAttr",
        sizeBits,
        inner.contentHash(oracle, cache, visited),
    )

    // The id is local-binding metadata; identity is the body. Drop
    // the "InlineDef" wrapper so this form is content-equivalent to
    // `Ref(id_at_same_content)` (see the Ref branch). Add the id to
    // `visited` so a back-edge inside the body (a forward Ref
    // pointing at this InlineDef's slot) stops recursing.
    is TypeDecl.InlineDef -> body.contentHash(oracle, cache, visited + id)
}

/**
 * Resolve [this] through [oracle] and recurse into the referenced body so
 * `Ref(id)` and the inline `InlineDef(id, body)` form converge on the
 * same hash (gcc emits both for the same logical content depending on
 * how a type was first introduced in each CU). [visited] guards against
 * self-referential cycles — `Range.of` always points at itself, and
 * struct fields can transitively reach back into the enclosing class.
 *
 * Resolve a Ref-shaped id through [oracle] and recurse into the body,
 * memoizing the result. `Ref(id)` and `InlineDef(id, content)` for the
 * same content converge on the same hash (gcc emits either form
 * depending on per-CU history). [visited] guards against self-referential
 * cycles — `Range.of` always points at itself; struct fields can
 * transitively reach back into the enclosing class.
 *
 * Caching strategy: store every successful (non-back-edge) result keyed
 * by [this]. For tree-shaped types the cached value is exact. For
 * mutually-recursive types the first computation wins and is reused —
 * mild inconsistency with what a from-scratch recomputation would
 * produce, but still deterministic across calls and good enough for
 * collision detection and DTM dedup.
 */
private fun GlobalTypeId.refKey(
    oracle: TypeAstOracle,
    cache: MutableMap<GlobalTypeId, Int>?,
    visited: Set<GlobalTypeId>,
): Int {
    if (this in visited) return BACK_EDGE_HASH
    cache?.get(this)?.let { return it }
    // Defense in depth: source-independent fallback for any unresolved id
    // that slips past the globalize-time `Builtin` hoist. Hashing the full
    // [GlobalTypeId] would bake `source` into the result and let per-CU
    // slots for the same logical builtin diverge.
    val referenced = oracle.byId(this) ?: return Objects.hash("unresolved", n)
    val h = referenced.body.contentHash(oracle, cache, visited + this)
    cache?.put(this, h)
    return h
}

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
    mangled,
    signature.contentHash(oracle, cache, visited),
    access,
    virt,
    isConst,
    isVolatile,
    vtableOffsetBits,
)
