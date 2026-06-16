package ghistabs.parse

import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DummySink
import ghistabs.harvest.Harvester
import ghistabs.harvest.TypeAst
import ghistabs.importer.StabOnlyAddressResolver
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Unit tests for Harvester.appendAsts() collision handling.
 *
 * Verifies stabs-algo-audit.AC3.2: XRef replacement, same-hash suppression,
 * hash-differing first-writer-wins, and same-type-twice behavior.
 *
 * Tests are pure unit tests (Kind 1): no Program/DataTypeManager/Listing,
 * only TaskMonitor.DUMMY, DummySink, and constructed test data.
 */
class HarvesterAppendAstsTest {
    private fun createTestHarvester(records: List<StabRecord> = emptyList()): Harvester {
        val harvester = Harvester(
            monitor = TaskMonitor.DUMMY,
            sink = DummySink,
            resolver = StabOnlyAddressResolver(),
        )
        harvester.preSeedHeaders(records)
        return harvester
    }

    /**
     * Test: XRef body replaced by concrete definition.
     *
     * 1. First appendAsts() with XRef body (forward reference).
     * 2. Second appendAsts() with Struct body (concrete definition).
     * 3. Assert typeAsts[id] contains Struct, not XRef.
     * 4. Assert collidingAsts does NOT contain entry (XRef replacement is not a collision).
     *
     * Source: stabs-canonicalization.md §6 (XRef replacement).
     */
    @Test
    fun testXRefReplacedByConcreteDefinition() {
        val cuName = "cu.c"
        // N_SO record establishes CU context; not needed by appendAsts() but kept for structural consistency
        val records = listOf(
            StabRecord(
                recordIndex = 0,
                type = StabType.N_SO,
                rawType = 0x00,
                other = 0,
                desc = 0,
                value = 0L,
                name = cuName,
            ),
        )
        val harvester = createTestHarvester(records = records)

        val globalId = GlobalTypeId(SourceFile.CUSource(cuName), 10)
        val xrefAst = TypeAst(
            cu = SourceFile.CUSource(cuName),
            id = globalId,
            name = "Foo",
            body = TypeDecl.XRef(kind = AggrKind.STRUCT, tagName = "Foo"),
        )
        val concreteStruct = TypeDecl.Struct(
            kind = AggrKind.STRUCT,
            sizeBytes = 16L,
            bases = emptyList(),
            fields = listOf(
                FieldDecl(
                    name = "x",
                    type = TypeDecl.Ref(GlobalTypeId(SourceFile.CUSource(cuName), 1)),
                    offsetBits = 0L,
                    sizeBits = 64L,
                    isStatic = false,
                ),
            ),
            methods = emptyList(),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )
        val concreteAst = TypeAst(
            cu = SourceFile.CUSource(cuName),
            id = globalId,
            name = "Foo",
            body = concreteStruct,
        )

        // Append XRef first, then concrete definition
        harvester.appendAsts(xrefAst)
        harvester.appendAsts(concreteAst)

        // Verify: typeAsts[id] contains Struct (replaced the XRef)
        val passBResult = harvester.passA(emptyList())
        assertTrue(passBResult.typeAsts.containsKey(globalId), "Type should be in typeAsts")
        val body = passBResult.typeAsts[globalId]!!.body
        assertTrue(body is TypeDecl.Struct, "Body should be Struct, not XRef")
        // Verify: collidingAsts should NOT contain entry
        assertTrue(
            !passBResult.collidingAsts.containsKey(globalId),
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
        val cuName = "cu.c"
        // N_SO record establishes CU context; not needed by appendAsts() but kept for structural consistency
        val records = listOf(
            StabRecord(
                recordIndex = 0,
                type = StabType.N_SO,
                rawType = 0x00,
                other = 0,
                desc = 0,
                value = 0L,
                name = cuName,
            ),
        )
        val harvester = createTestHarvester(records = records)

        val globalId = GlobalTypeId(SourceFile.CUSource(cuName), 20)
        val body = TypeDecl.Struct(
            kind = AggrKind.STRUCT,
            sizeBytes = 8L,
            bases = emptyList(),
            fields = emptyList(),
            methods = emptyList(),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )

        val ast1 = TypeAst(
            cu = SourceFile.CUSource(cuName),
            id = globalId,
            name = "Bar",
            body = body,
        )
        val ast2 = TypeAst(
            cu = SourceFile.CUSource(cuName),
            id = globalId,
            name = "Bar",
            body = body,
        )

        // Append both (same hash)
        harvester.appendAsts(ast1, ast2)

        // Verify: exactly one entry exists
        val passBResult = harvester.passA(emptyList())
        assertEquals(1, passBResult.typeAsts.size, "Should have exactly one entry after same-hash append")
        // Verify: collidingAsts should NOT contain entry
        assertTrue(
            !passBResult.collidingAsts.containsKey(globalId),
            "Same-hash should not create collision entry",
        )
    }

    /**
     * Test: Hash-differing first-writer-wins.
     *
     * 1. Construct two TypeAst with same GlobalTypeId but different struct field counts.
     * 2. Call appendAsts([first]), then appendAsts([second]).
     * 3. Assert typeAsts[id].body equals first body (first writer wins).
     * 4. Assert collidingAsts[id] is non-empty (collision recorded).
     *
     * Source: stabs-canonicalization.md §4 (hash-differing first-writer-wins).
     */
    @Test
    fun testHashDifferingFirstWriterWins() {
        val cuName = "cu.c"
        // N_SO record establishes CU context; not needed by appendAsts() but kept for structural consistency
        val records = listOf(
            StabRecord(
                recordIndex = 0,
                type = StabType.N_SO,
                rawType = 0x00,
                other = 0,
                desc = 0,
                value = 0L,
                name = cuName,
            ),
        )
        val harvester = createTestHarvester(records = records)

        val globalId = GlobalTypeId(SourceFile.CUSource(cuName), 30)

        val firstBody = TypeDecl.Struct(
            kind = AggrKind.STRUCT,
            sizeBytes = 8L,
            bases = emptyList(),
            fields = listOf(
                FieldDecl(
                    name = "x",
                    type = TypeDecl.Ref(GlobalTypeId(SourceFile.CUSource(cuName), 1)),
                    offsetBits = 0L,
                    sizeBits = 32L,
                    isStatic = false,
                ),
            ),
            methods = emptyList(),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )

        val secondBody = TypeDecl.Struct(
            kind = AggrKind.STRUCT,
            sizeBytes = 16L,
            bases = emptyList(),
            fields = listOf(
                FieldDecl(
                    name = "x",
                    type = TypeDecl.Ref(GlobalTypeId(SourceFile.CUSource(cuName), 1)),
                    offsetBits = 0L,
                    sizeBits = 32L,
                    isStatic = false,
                ),
                FieldDecl(
                    name = "y",
                    type = TypeDecl.Ref(GlobalTypeId(SourceFile.CUSource(cuName), 2)),
                    offsetBits = 32L,
                    sizeBits = 32L,
                    isStatic = false,
                ),
            ),
            methods = emptyList(),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )

        val firstAst = TypeAst(
            cu = SourceFile.CUSource(cuName),
            id = globalId,
            name = "Baz",
            body = firstBody,
        )
        val secondAst = TypeAst(
            cu = SourceFile.CUSource(cuName),
            id = globalId,
            name = "Baz",
            body = secondBody,
        )

        // Append first, then second (different hashes)
        harvester.appendAsts(firstAst)
        harvester.appendAsts(secondAst)

        // Verify: typeAsts[id].body equals first body
        val passBResult = harvester.passA(emptyList())
        assertEquals(firstBody, passBResult.typeAsts[globalId]!!.body, "First writer should win")
        // Verify: collidingAsts[id] is non-empty
        assertTrue(
            passBResult.collidingAsts.containsKey(globalId),
            "Hash-differing bodies should create collision entry",
        )
        assertTrue(
            passBResult.collidingAsts[globalId]!!.isNotEmpty(),
            "Collision entry should be non-empty",
        )
    }

    /**
     * Test: Same type twice from same CU (duplicate with same hash).
     *
     * This mirrors the bouniaf same-hash pattern. Two stabs records in the same CU
     * define the same type (same GlobalTypeId) with identical bodies.
     *
     * 1. Append the same TypeAst twice.
     * 2. Assert typeAsts contains exactly one entry (duplicate suppressed).
     * 3. Assert collidingAsts does not contain entry (not a collision, just a duplicate).
     */
    @Test
    fun testSameTypeTwiceFromSameCU() {
        val cuName = "cu.c"
        // N_SO record establishes CU context; not needed by appendAsts() but kept for structural consistency
        val records = listOf(
            StabRecord(
                recordIndex = 0,
                type = StabType.N_SO,
                rawType = 0x00,
                other = 0,
                desc = 0,
                value = 0L,
                name = cuName,
            ),
        )
        val harvester = createTestHarvester(records = records)

        val globalId = GlobalTypeId(SourceFile.CUSource(cuName), 40)
        val body = TypeDecl.Enum<GlobalTypeId>(members = listOf("A" to 0L, "B" to 1L))
        val ast = TypeAst(
            cu = SourceFile.CUSource(cuName),
            id = globalId,
            name = "EnumType",
            body = body,
        )

        // Append twice
        harvester.appendAsts(ast)
        harvester.appendAsts(ast)

        // Verify: exactly one entry
        val passBResult = harvester.passA(emptyList())
        assertEquals(1, passBResult.typeAsts.size, "Should have exactly one entry after duplicate append")
        // Verify: collidingAsts should NOT contain entry
        assertTrue(
            !passBResult.collidingAsts.containsKey(globalId),
            "Duplicate should not create collision entry",
        )
    }
}
