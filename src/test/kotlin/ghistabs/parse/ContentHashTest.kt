package ghistabs.parse

import ghistabs.harvest.TypeAst
import ghistabs.harvest.TypeAstOracle
import ghistabs.harvest.contentHash
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test

/**
 * Pins the content-equivalence semantics of [contentHash]: per-CU
 * template-instantiation clones must collapse into a single canonical
 * hash, while structurally-different types must remain distinct.
 *
 * The bouniafbouniaf harvest shows ~208 collisions of the form "same
 * GlobalTypeId for `pair<int, X*>`, different bodies because each CU's
 * inner Refs point at CU-local primitive-type ids". After this hash
 * change those collide-into-same instead of collide-into-different.
 */
class ContentHashTest {
    private val intInCU1 = TypeAst(
        cu = SourceFile.CUSource("a.cpp"),
        id = GlobalTypeId(SourceFile.CUSource("a.cpp"), 1),
        name = "int",
        body = TypeDecl.Range(GlobalTypeId(SourceFile.CUSource("a.cpp"), 1), -2147483648L, 2147483647L),
    )

    private val intInCU2 = TypeAst(
        cu = SourceFile.CUSource("b.cpp"),
        id = GlobalTypeId(SourceFile.CUSource("b.cpp"), 1),
        name = "int",
        body = TypeDecl.Range(GlobalTypeId(SourceFile.CUSource("b.cpp"), 1), -2147483648L, 2147483647L),
    )

    private val charInCU1 = TypeAst(
        cu = SourceFile.CUSource("a.cpp"),
        id = GlobalTypeId(SourceFile.CUSource("a.cpp"), 2),
        name = "char",
        body = TypeDecl.Range(GlobalTypeId(SourceFile.CUSource("a.cpp"), 2), 0L, 127L),
    )

    private val asts = mapOf(
        intInCU1.id to intInCU1,
        intInCU2.id to intInCU2,
        charInCU1.id to charInCU1,
    )

    private val oracle = TypeAstOracle(asts::get)

    /**
     * `Ref(cu=a.cpp, n=1)` and `Ref(cu=b.cpp, n=1)` both point at "int"
     * Range types. Old behaviour: distinct hashes (id differs). New
     * behaviour: identical hashes (name + body-kind match).
     */
    @Test
    fun refsToSameNamedTypeFromDifferentCUsHashIdentically() {
        val refToIntFromCU1 = TypeDecl.Ref(intInCU1.id)
        val refToIntFromCU2 = TypeDecl.Ref(intInCU2.id)
        assertEquals(refToIntFromCU1.contentHash(oracle), refToIntFromCU2.contentHash(oracle))
    }

    @Test
    fun refsToDifferentlyNamedTypesHashDifferently() {
        val refToInt = TypeDecl.Ref(intInCU1.id)
        val refToChar = TypeDecl.Ref(charInCU1.id)
        assertNotEquals(refToInt.contentHash(oracle), refToChar.contentHash(oracle))
    }

    /**
     * Per-CU `bool` slots are encoded as `WithSizeAttr(8, Builtin(-16))`
     * after [ghistabs.harvest.Harvester.globalize] hoists the negative-id Ref. Two CUs
     * therefore both encode `bool` as `WithSizeAttr(8, Builtin(-16))`
     * — same content, must hash equally. Before the Builtin hoist this
     * was `WithSizeAttr(8, Ref([CU_X, -16]))`, which fell through to
     * [contentHash]'s `unresolved` fallback and baked the source CU
     * into the hash → per-CU divergence → 3 spurious "real" collisions
     * in bouniafbouniaf.
     */
    @Test
    fun perCuBoolSlotHashesEqual() {
        val boolInCU1 = TypeAst(
            cu = SourceFile.CUSource("a.cpp"),
            id = GlobalTypeId(SourceFile.CUSource("a.cpp"), 21),
            name = "bool",
            body = TypeDecl.WithSizeAttr(8, TypeDecl.Builtin(-16)),
        )
        val boolInCU2 = TypeAst(
            cu = SourceFile.CUSource("b.cpp"),
            id = GlobalTypeId(SourceFile.CUSource("b.cpp"), 21),
            name = "bool",
            body = TypeDecl.WithSizeAttr(8, TypeDecl.Builtin(-16)),
        )
        val store = mapOf(boolInCU1.id to boolInCU1, boolInCU2.id to boolInCU2)
        val o = TypeAstOracle(store::get)
        assertEquals(boolInCU1.body.contentHash(o), boolInCU2.body.contentHash(o))
        // And the Refs into them — what the surrounding struct's field
        // type expression actually looks like — must agree too.
        assertEquals(
            TypeDecl.Ref(boolInCU1.id).contentHash(o),
            TypeDecl.Ref(boolInCU2.id).contentHash(o),
        )
    }

    @Test
    fun unresolvedRefStillHashesDeterministically() {
        val phantom = GlobalTypeId(SourceFile.CUSource("ghost.cpp"), 999)
        val ref = TypeDecl.Ref<GlobalTypeId>(phantom)
        // Two evaluations of the same unresolved ref agree with each
        // other; the unresolved branch must be deterministic so
        // collision detection isn't randomised.
        assertEquals(ref.contentHash(oracle), ref.contentHash(oracle))
    }

    /**
     * The motivating bouniafbouniaf case: per-CU `pair<int, X*>` clones with
     * structurally-identical field-name-and-kind layouts collide-into-
     * same despite living at distinct GlobalTypeIds.
     */
    @Test
    fun perCuTemplateClonesHashIdentically() {
        val clone1Body = TypeDecl.Struct<GlobalTypeId>(
            rawKind = AggrKind.STRUCT,
            sizeBytes = 8L,
            bases = emptyList(),
            fields = listOf(
                FieldDecl(
                    name = "first",
                    type = TypeDecl.Ref(intInCU1.id),
                    offsetBits = 0L,
                    sizeBits = 32L,
                    isStatic = false,
                ),
            ),
            methods = emptyList(),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )
        val clone2Body = clone1Body.copy(
            fields = listOf(
                clone1Body.fields[0].copy(type = TypeDecl.Ref(intInCU2.id)),
            ),
        )
        assertEquals(clone1Body.contentHash(oracle), clone2Body.contentHash(oracle))
    }

    @Test
    fun structurallyDifferentStructsHashDifferently() {
        val s1 = TypeDecl.Struct<GlobalTypeId>(
            rawKind = AggrKind.STRUCT,
            sizeBytes = 4L,
            bases = emptyList(),
            fields = listOf(
                FieldDecl(
                    name = "x",
                    type = TypeDecl.Ref(intInCU1.id),
                    offsetBits = 0L,
                    sizeBits = 32L,
                    isStatic = false,
                ),
            ),
            methods = emptyList(),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )
        val s2 = s1.copy(
            fields = listOf(s1.fields[0].copy(type = TypeDecl.Ref(charInCU1.id))),
        )
        assertNotEquals(s1.contentHash(oracle), s2.contentHash(oracle))
    }

    /**
     * `InlineDef` carries its own GlobalTypeId for local-binding
     * purposes, but the identity is the body. Two InlineDefs with the
     * same body but different binding ids must hash identically — as
     * long as the body doesn't transitively reference the binding id
     * (which would be self-referential and engage the cycle break).
     */
    @Test
    fun inlineDefHashesByBodyNotById() {
        val body = TypeDecl.Pointer<GlobalTypeId>(TypeDecl.Ref(charInCU1.id))
        val inline1 = TypeDecl.InlineDef(intInCU1.id, body)
        val inline2 = TypeDecl.InlineDef(intInCU2.id, body)
        assertEquals(inline1.contentHash(oracle), inline2.contentHash(oracle))
    }

    /**
     * Motivating asymmetry: gcc may emit a type as a `Ref` in one CU
     * and as a fully-inlined `InlineDef(id, body)` in another. With Ref
     * and InlineDef both reducing to the wrapped content, both forms
     * hash identically.
     */
    @Test
    fun refAndInlineDefHashIdenticallyWhenContentMatches() {
        // CU3 owns a Pointer-to-int type at id_3.
        val pointerToInt = TypeAst(
            cu = SourceFile.CUSource("c.cpp"),
            id = GlobalTypeId(SourceFile.CUSource("c.cpp"), 7),
            name = "[c.cpp,7]",
            body = TypeDecl.Pointer(TypeDecl.Ref(intInCU1.id)),
        )
        val asts2 = asts + (pointerToInt.id to pointerToInt)
        val oracle2: TypeAstOracle = TypeAstOracle(asts2::get)
        // Form A: a Ref pointing at the Pointer-to-int type.
        val asRef = TypeDecl.Ref<GlobalTypeId>(pointerToInt.id)
        // Form B: the Pointer inlined at a different id.
        val asInline = TypeDecl.InlineDef<GlobalTypeId>(
            GlobalTypeId(SourceFile.CUSource("d.cpp"), 99),
            TypeDecl.Pointer(TypeDecl.Ref(intInCU1.id)),
        )
        assertEquals(asRef.contentHash(oracle2), asInline.contentHash(oracle2))
    }

    /**
     * Cycle protection: a `Range.of` always points back at the Range
     * itself. `contentHash` must terminate.
     */

    /**
     * Regression: gcc emits `InlineDef(id=98, body=XRef(STRUCT, _IO_FILE))`
     * as a forward-reference alias for id 97, while id 98 holds the actual
     * Struct body. The InlineDef branch adds 98 to `visited` before recursing
     * into the XRef body; `byXRef` resolves to id 98; refKey sees 98 in
     * visited and returns BACK_EDGE_HASH — a false cycle.
     *
     * After the fix, XRef checks the visited set itself and, when the
     * resolved id is already marked, calls body.contentHash directly instead
     * of going through refKey, yielding the correct Struct hash.
     */
    @Test
    fun xRefResolvingToInlineDefIdIsNotACycle() {
        val cu = SourceFile.CUSource("/xml/xmltest.cpp")
        // id 98: the actual _IO_FILE struct definition
        val id98 = GlobalTypeId(cu, 98)
        val intId = GlobalTypeId(cu, 2)
        val intAst = TypeAst(cu, intId, "int", TypeDecl.Range(intId, -2147483648L, 2147483647L))
        val ioFileBody = TypeDecl.Struct<GlobalTypeId>(
            rawKind = AggrKind.STRUCT,
            sizeBytes = 216,
            bases = emptyList(),
            fields = listOf(FieldDecl("_flags", TypeDecl.Ref(intId), 0L, 32L, false)),
            methods = emptyList(),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )
        val ioFileAst = TypeAst(cu, id98, "_IO_FILE", ioFileBody)
        // id 97: InlineDef(id=98, body=XRef(STRUCT, _IO_FILE)) — the forward-ref alias
        val id97 = GlobalTypeId(cu, 97)
        val forwardAlias = TypeAst(
            cu,
            id97,
            null,
            TypeDecl.InlineDef(id98, TypeDecl.XRef(AggrKind.STRUCT, "_IO_FILE")),
        )

        val store = mapOf(id97 to forwardAlias, id98 to ioFileAst, intId to intAst)
        val o = TypeAstOracle(
            byId = store::get,
            byXRef = { xref -> store.values.firstOrNull { it.name == xref.tagName } },
        )

        // Ref(97) must hash to the same value as the actual struct body
        val hashViaForwardRef = TypeDecl.Ref<GlobalTypeId>(id97).contentHash(o)
        val hashViaDirectRef = ioFileBody.contentHash(o)
        assertEquals(
            hashViaDirectRef,
            hashViaForwardRef,
            "forward-ref alias must hash as the struct body, not BACK_EDGE_HASH",
        )
    }

    @Test
    fun selfReferentialTypeTerminates() {
        val h = intInCU1.body.contentHash(oracle)
        // Plain assertion that it returned; if it had infinite-looped
        // we'd never get here.
        assertNotEquals(0, h)
    }

    /**
     * Mirror of the bouniafbouniaf `pair<const int, CSourceSymbolData*>`
     * collision case: two CUs each emit the same outer pair struct;
     * CU1 expresses an inner Pointer-to-self via `Ref(id_A)` where
     * `id_A` is a separately-emitted TypeAst, CU2 expresses it as
     * `InlineDef(id_B, Pointer(Ref(pair_id)))` inline. After harvest
     * both forms should hash identically — they're the same logical
     * type. If they don't, classifyCollisions buckets them as "real"
     * when they're actually spurious.
     *
     * Faithful replay of the bouniafbouniaf `[sym.h,87]` pair-collision:
     * the outer Struct itself has self-referential methods (cls=Ref to
     * the pair id), and the variants differ only in how param[0] of
     * one method is expressed (Ref vs InlineDef). typeAsts contains
     * the canonical (variant_0) pair body plus the separately-emitted
     * Pointer-to-pair entries at both [Keywords.cpp,180] and
     * [assemble.cpp,229] (both with body=Pointer(Ref(pairId))).
     *
     * Both variants must hash identically — the actual harvest
     * classifyCollisions sees them diverge, so this test reproduces
     * the failing path in isolation.
     */
    @Test
    fun pairStructWithSelfRefMethodsRefVsInlineDefParamHashesEqual() {
        val pairId = GlobalTypeId(
            SourceFile.HeaderSource(
                HeaderFile("sym.h", checksum = 1L, originatingCu = SourceFile.CUSource("Keywords.cpp")),
            ),
            87,
        )
        val intId = GlobalTypeId(SourceFile.CUSource("Keywords.cpp"), 40)
        val ptrAId = GlobalTypeId(SourceFile.CUSource("Keywords.cpp"), 180)
        val ptrBId = GlobalTypeId(SourceFile.CUSource("assemble.cpp"), 229)
        val methodBindAId = GlobalTypeId(SourceFile.CUSource("Keywords.cpp"), 440)
        val methodBindBId = GlobalTypeId(SourceFile.CUSource("assemble.cpp"), 228)

        fun makePairBody(param0: TypeDecl<GlobalTypeId>): TypeDecl.Struct<GlobalTypeId> = TypeDecl.Struct(
            rawKind = AggrKind.STRUCT,
            sizeBytes = 8L,
            bases = emptyList(),
            fields = listOf(
                FieldDecl("first", TypeDecl.Ref(intId), 0L, 32L, false),
            ),
            methods = listOf(
                MethodDecl(
                    name = "operator=",
                    mangled = null,
                    signature = TypeDecl.InlineDef(
                        if (param0 is TypeDecl.Ref<*>) methodBindAId else methodBindBId,
                        TypeDecl.Method(
                            cls = TypeDecl.Ref(pairId),
                            ret = TypeDecl.Ref(intId),
                            params = listOf(param0),
                        ),
                    ),
                    access = Access.PUBLIC,
                    virt = VirtKind.NORMAL,
                    isConst = false,
                    isVolatile = false,
                    vtableOffsetBits = null,
                ),
            ),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )

        val variant0 = makePairBody(TypeDecl.Ref(ptrAId))
        val variant1 = makePairBody(
            TypeDecl.InlineDef(ptrBId, TypeDecl.Pointer(TypeDecl.Ref(pairId))),
        )

        val keywordsCu = SourceFile.CUSource("Keywords.cpp")
        val assembleCu = SourceFile.CUSource("assemble.cpp")
        val pairCanonical = TypeAst(cu = keywordsCu, id = pairId, name = "pair", body = variant0)
        val ptrA =
            TypeAst(
                cu = keywordsCu,
                id = ptrAId,
                name = "[Keywords.cpp,180]",
                body = TypeDecl.Pointer(TypeDecl.Ref(pairId)),
            )
        val ptrB =
            TypeAst(
                cu = assembleCu,
                id = ptrBId,
                name = "[assemble.cpp,229]",
                body = TypeDecl.Pointer(TypeDecl.Ref(pairId)),
            )
        val intAst =
            TypeAst(cu = keywordsCu, id = intId, name = "int", body = TypeDecl.Range(intId, -2147483648L, 2147483647L))
        val store = mapOf(pairId to pairCanonical, ptrAId to ptrA, ptrBId to ptrB, intId to intAst)
        val storeOracle: TypeAstOracle = TypeAstOracle(store::get)

        // Pre-populate the cache the same way the dump test does:
        // hash every TypeAst.body top-level, then store under its id.
        val cache = mutableMapOf<GlobalTypeId, Int>()
        for (ast in store.values) {
            cache[ast.id] = ast.body.contentHash(storeOracle, cache)
        }

        val h0 = variant0.contentHash(storeOracle, cache)
        val h1 = variant1.contentHash(storeOracle, cache)
        assertEquals(h0, h1, "variant_0 (Ref param) and variant_1 (InlineDef param) must hash identically")
    }

    @Test
    fun refToSeparatelyEmittedTypeEqualsEquivalentInlineDef() {
        // pair_id is the outer "pair" struct's GlobalTypeId.
        val pairCu = SourceFile.HeaderSource(
            HeaderFile("sym.h", checksum = 1L, originatingCu = SourceFile.CUSource("a.cpp")),
        )
        val pairId = GlobalTypeId(pairCu, 87)
        // CU1's separately-emitted Pointer-to-pair at id 180 in CU1.
        val ptrInA = TypeAst(
            cu = SourceFile.CUSource("a.cpp"),
            id = GlobalTypeId(SourceFile.CUSource("a.cpp"), 180),
            name = "[a.cpp,180]",
            body = TypeDecl.Pointer(TypeDecl.Ref(pairId)),
        )
        // CU2's inline form would emit a TypeAst from walkDefinitions too.
        val ptrInB = TypeAst(
            cu = SourceFile.CUSource("b.cpp"),
            id = GlobalTypeId(SourceFile.CUSource("b.cpp"), 229),
            name = "[b.cpp,229]",
            body = TypeDecl.Pointer(TypeDecl.Ref(pairId)),
        )
        val store = mapOf(ptrInA.id to ptrInA, ptrInB.id to ptrInB)
        val storeOracle: TypeAstOracle = TypeAstOracle(store::get)

        // Form A: a Ref to ptrInA.
        val formA = TypeDecl.Ref<GlobalTypeId>(ptrInA.id)
        // Form B: an InlineDef wrapping the same Pointer content, with
        // a different binding id (mimics the CU2 inline path).
        val formB = TypeDecl.InlineDef<GlobalTypeId>(
            GlobalTypeId(SourceFile.CUSource("b.cpp"), 999),
            TypeDecl.Pointer(TypeDecl.Ref(pairId)),
        )

        assertEquals(formA.contentHash(storeOracle), formB.contentHash(storeOracle))
    }
}
