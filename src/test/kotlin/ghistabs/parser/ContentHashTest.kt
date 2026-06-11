package ghistabs.parser

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

    private val oracle: (GlobalTypeId) -> TypeAst? = asts::get

    /**
     * `Ref(cu=a.cpp, n=1)` and `Ref(cu=b.cpp, n=1)` both point at "int"
     * Range types. Old behaviour: distinct hashes (id differs). New
     * behaviour: identical hashes (name + body-kind match).
     */
    @Test
    fun refsToSameNamedTypeFromDifferentCUsHashIdentically() {
        val refToIntFromCU1 = TypeDecl.Ref(intInCU1.id)
        val refToIntFromCU2 = TypeDecl.Ref(intInCU2.id)
        assertEquals(contentHash(refToIntFromCU1, oracle), contentHash(refToIntFromCU2, oracle))
    }

    @Test
    fun refsToDifferentlyNamedTypesHashDifferently() {
        val refToInt = TypeDecl.Ref(intInCU1.id)
        val refToChar = TypeDecl.Ref(charInCU1.id)
        assertNotEquals(contentHash(refToInt, oracle), contentHash(refToChar, oracle))
    }

    @Test
    fun unresolvedRefStillHashesDeterministically() {
        val phantom = GlobalTypeId(SourceFile.CUSource("ghost.cpp"), 999)
        val ref = TypeDecl.Ref<GlobalTypeId>(phantom)
        // Two evaluations of the same unresolved ref agree with each
        // other; the unresolved branch must be deterministic so
        // collision detection isn't randomised.
        assertEquals(contentHash(ref, oracle), contentHash(ref, oracle))
    }

    /**
     * The motivating bouniafbouniaf case: per-CU `pair<int, X*>` clones with
     * structurally-identical field-name-and-kind layouts collide-into-
     * same despite living at distinct GlobalTypeIds.
     */
    @Test
    fun perCuTemplateClonesHashIdentically() {
        val clone1Body = TypeDecl.Struct<GlobalTypeId>(
            kind = AggrKind.STRUCT,
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
        assertEquals(contentHash(clone1Body, oracle), contentHash(clone2Body, oracle))
    }

    @Test
    fun structurallyDifferentStructsHashDifferently() {
        val s1 = TypeDecl.Struct<GlobalTypeId>(
            kind = AggrKind.STRUCT,
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
        assertNotEquals(contentHash(s1, oracle), contentHash(s2, oracle))
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
        assertEquals(contentHash(inline1, oracle), contentHash(inline2, oracle))
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
        val oracle2: (GlobalTypeId) -> TypeAst? = asts2::get
        // Form A: a Ref pointing at the Pointer-to-int type.
        val asRef = TypeDecl.Ref<GlobalTypeId>(pointerToInt.id)
        // Form B: the Pointer inlined at a different id.
        val asInline = TypeDecl.InlineDef<GlobalTypeId>(
            GlobalTypeId(SourceFile.CUSource("d.cpp"), 99),
            TypeDecl.Pointer(TypeDecl.Ref(intInCU1.id)),
        )
        assertEquals(contentHash(asRef, oracle2), contentHash(asInline, oracle2))
    }

    /**
     * Cycle protection: a `Range.of` always points back at the Range
     * itself. `contentHash` must terminate.
     */
    @Test
    fun selfReferentialTypeTerminates() {
        val h = contentHash(intInCU1.body, oracle)
        // Plain assertion that it returned; if it had infinite-looped
        // we'd never get here.
        assertNotEquals(0, h)
    }
}
