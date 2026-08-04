package ghistabs.harvest

import ghistabs.parse.*
import ghistabs.parse.TypeDecl.Struct.Field
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Unit tests for Harvester.appendAsts() collision handling.
 *
 * Verifies stabs-algo-audit.AC3.2: XRef replacement, same-hash suppression,
 * hash-differing first-writer-wins, and same-type-twice behavior.
 */
class TypeStoreTest {

    /**
     * Test: XRef body replaced by concrete definition.
     *
     * 1. First appendAsts() with XRef body (forward reference).
     * 2. Second appendAsts() with Struct body (concrete definition).
     * 3. Assert `typeAsts[id]` contains Struct, not XRef.
     * 4. Assert collidingAsts does NOT contain entry (XRef replacement is not a collision).
     *
     * Source: stabs-canonicalization.md §6 (XRef replacement).
     */
    @Test
    fun testXRefReplacedByConcreteDefinition() {
        val store = TypeStore()
        val cuName = "cu.c"

        val globalId = GlobalTypeId(SourceFile.CUSource(cuName), 10)
        val xrefAst = Type(
            cu = SourceFile.CUSource(cuName),
            id = globalId,
            name = "Foo",
            body = TypeDecl.XRef(kind = AggrKind.STRUCT, tagName = "Foo"),
        )
        val concreteStruct = TypeDecl.Struct(
            rawKind = AggrKind.STRUCT,
            sizeBytes = 16L,
            bases = emptyList(),
            fields = listOf(
                Field(
                    name = "x",
                    type = TypeDecl.Ref(GlobalTypeId(SourceFile.CUSource(cuName), 1)),
                    offsetBits = 0L,
                    sizeBits = 64L,
                    isStatic = false,
                    access = Access.PUBLIC,
                    mangled = null,
                ),
            ),
            methods = emptyList(),
            vptrBasetype = null,
        )
        val concreteAst = Type(
            cu = SourceFile.CUSource(cuName),
            id = globalId,
            name = "Foo",
            body = concreteStruct,
        )

        // Append XRef first, then concrete definition
        store += xrefAst
        store += concreteAst

        // Verify: typeAsts[id] contains Struct (replaced the XRef)
        val (typeAsts, rawCollisions) = store.toHarvest()
        assertTrue(typeAsts.containsKey(globalId), "Type should be in typeAsts")
        val body = typeAsts[globalId]!!.body
        assertTrue(body is TypeDecl.Struct, "Body should be Struct, not XRef")
        // Verify: collidingAsts should NOT contain entry
        assertTrue(
            !rawCollisions.containsKey(globalId),
            "XRef replacement should not create collision entry",
        )
    }

    /**
     * Test: Same-hash suppression (duplicate suppressed silently).
     *
     * 1. Construct two TypeAst with same GlobalTypeId and bodies with same hash.
     * 2. Call appendAsts() with both.
     * 3. Assert typeAsts contains exactly one entry.
     * 4. Assert collidingAsts does NOT contain entry.
     *
     * Source: stabs-canonicalization.md §4 (same-hash suppression).
     */
    @Test
    fun testSameHashSuppression() {
        val store = TypeStore()
        val cuName = "cu.c"

        val globalId = GlobalTypeId(SourceFile.CUSource(cuName), 20)
        val body = TypeDecl.Struct<GlobalTypeId>(
            rawKind = AggrKind.STRUCT,
            sizeBytes = 8L,
            bases = emptyList(),
            fields = emptyList(),
            methods = emptyList(),
            vptrBasetype = null,
        )

        val ast1 = Type(
            cu = SourceFile.CUSource(cuName),
            id = globalId,
            name = "Bar",
            body = body,
        )
        val ast2 = Type(
            cu = SourceFile.CUSource(cuName),
            id = globalId,
            name = "Bar",
            body = body,
        )

        // Append both (same hash)
        store += ast1
        store += ast2

        // Verify: exactly one entry exists
        val (typeAsts, rawCollisions) = store.toHarvest()
        assertEquals(1, typeAsts.size, "Should have exactly one entry after same-hash append")
        // Verify: collidingAsts should NOT contain entry
        assertTrue(
            !rawCollisions.containsKey(globalId),
            "Same-hash should not create collision entry",
        )
    }

    /**
     * Test: Hash-differing first-writer-wins.
     *
     * 1. Construct two TypeAst with same GlobalTypeId but different struct field counts.
     * 2. Call `appendAsts(first)`, then `appendAsts(second)`.
     * 3. Assert `typeAsts[id].body` equals first body (first writer wins).
     * 4. Assert `collidingAsts[id]` is non-empty (collision recorded).
     *
     * Source: stabs-canonicalization.md §4 (hash-differing first-writer-wins).
     */
    @Test
    fun testHashDifferingFirstWriterWins() {
        val store = TypeStore()
        val cuName = "cu.c"

        val globalId = GlobalTypeId(SourceFile.CUSource(cuName), 30)

        val firstBody = TypeDecl.Struct(
            rawKind = AggrKind.STRUCT,
            sizeBytes = 8L,
            bases = emptyList(),
            fields = listOf(
                Field(
                    name = "x",
                    type = TypeDecl.Ref(GlobalTypeId(SourceFile.CUSource(cuName), 1)),
                    offsetBits = 0L,
                    sizeBits = 32L,
                    isStatic = false,
                    access = Access.PUBLIC,
                    mangled = null,
                ),
            ),
            methods = emptyList(),
            vptrBasetype = null,
        )

        val secondBody = TypeDecl.Struct(
            rawKind = AggrKind.STRUCT,
            sizeBytes = 16L,
            bases = emptyList(),
            fields = listOf(
                Field(
                    name = "x",
                    type = TypeDecl.Ref(GlobalTypeId(SourceFile.CUSource(cuName), 1)),
                    offsetBits = 0L,
                    sizeBits = 32L,
                    isStatic = false,
                    access = Access.PUBLIC,
                    mangled = null,
                ),
                Field(
                    name = "y",
                    type = TypeDecl.Ref(GlobalTypeId(SourceFile.CUSource(cuName), 2)),
                    offsetBits = 32L,
                    sizeBits = 32L,
                    isStatic = false,
                    access = Access.PUBLIC,
                    mangled = null,
                ),
            ),
            methods = emptyList(),
            vptrBasetype = null,
        )

        val firstAst = Type(
            cu = SourceFile.CUSource(cuName),
            id = globalId,
            name = "Baz",
            body = firstBody,
        )
        val secondAst = Type(
            cu = SourceFile.CUSource(cuName),
            id = globalId,
            name = "Baz",
            body = secondBody,
        )

        // Append first, then second (different hashes)
        store += firstAst
        store += secondAst

        // Verify: typeAsts[id].body equals first body
        val (typeAsts, rawCollisions) = store.toHarvest()
        assertEquals(firstBody, typeAsts[globalId]!!.body, "First writer should win")
        // Verify: collidingAsts[id] is non-empty
        assertTrue(
            rawCollisions.containsKey(globalId),
            "Hash-differing bodies should create collision entry",
        )
        assertTrue(
            rawCollisions[globalId]!!.isNotEmpty(),
            "Collision entry should be non-empty",
        )
    }

    /**
     * Test: a lone self-referential typedef (`void:t(0,20)=(0,20)`) survives rather than being
     * skipped — TypeRegistry's void detection needs the ast present to map it to VoidDataType.
     */
    @Test
    fun testLoneSelfRefTypedefSurvives() {
        val store = TypeStore()
        val cuName = "cu.c"
        val id = GlobalTypeId(SourceFile.CUSource(cuName), 20)
        store += Type(cu = SourceFile.CUSource(cuName), id = id, name = "void", body = TypeDecl.Ref(id))

        val (typeAsts, _) = store.toHarvest()
        val body = typeAsts[id]?.body
        assertTrue(body is TypeDecl.Ref && body.id == id, "lone self-ref (void) must survive, not be skipped")
    }

    /**
     * Test: a concrete body always wins over a self-ref at the same id, in either arrival order.
     * This is the box2d case — a bare re-declaration must not demote a real struct to void.
     */
    @Test
    fun testConcreteBodySupersedesSelfRef() {
        val cuName = "cu.c"
        val id = GlobalTypeId(SourceFile.CUSource(cuName), 20)
        val selfRef = Type(cu = SourceFile.CUSource(cuName), id = id, name = "Foo", body = TypeDecl.Ref(id))
        val struct = TypeDecl.Struct(
            rawKind = AggrKind.STRUCT,
            sizeBytes = 8L,
            bases = emptyList(),
            fields = listOf(
                Field(
                    "x",
                    TypeDecl.Ref(GlobalTypeId(SourceFile.CUSource(cuName), 1)),
                    0L,
                    32L,
                    false,
                    Access.PUBLIC,
                    mangled = null,
                ),
            ),
            methods = emptyList(),
            vptrBasetype = null,
        )
        val concrete = Type(cu = SourceFile.CUSource(cuName), id = id, name = "Foo", body = struct)

        val selfRefFirst = TypeStore().apply {
            this += selfRef
            this += concrete
        }
        assertEquals(struct, selfRefFirst.toHarvest().first[id]!!.body, "real body supersedes self-ref")

        val concreteFirst = TypeStore().apply {
            this += concrete
            this += selfRef
        }
        assertEquals(
            struct,
            concreteFirst.toHarvest().first[id]!!.body,
            "self-ref never demotes a real body",
        )
    }

    /**
     * Test: Same type twice from same CU (duplicate with same hash).
     *
     * This mirrors the appquery same-hash pattern. Two stabs records in the same CU
     * define the same type (same GlobalTypeId) with identical bodies.
     *
     * 1. Append the same TypeAst twice.
     * 2. Assert typeAsts contains exactly one entry (duplicate suppressed).
     * 3. Assert collidingAsts does not contain entry (not a collision, just a duplicate).
     */
    @Test
    fun testSameTypeTwiceFromSameCU() {
        val store = TypeStore()
        val cuName = "cu.c"

        val globalId = GlobalTypeId(SourceFile.CUSource(cuName), 40)
        val body = TypeDecl.Enum<GlobalTypeId>(members = listOf("A" to 0L, "B" to 1L))
        val ast = Type(
            cu = SourceFile.CUSource(cuName),
            id = globalId,
            name = "EnumType",
            body = body,
        )

        // Append twice
        store += ast
        store += ast

        // Verify: exactly one entry
        val (typeAsts, rawCollisions) = store.toHarvest()
        assertEquals(1, typeAsts.size, "Should have exactly one entry after duplicate append")
        // Verify: collidingAsts should NOT contain entry
        assertTrue(
            !rawCollisions.containsKey(globalId),
            "Duplicate should not create collision entry",
        )
    }
}
