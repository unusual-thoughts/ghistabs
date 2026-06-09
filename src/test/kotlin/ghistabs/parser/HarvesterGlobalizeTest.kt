package ghistabs.parser

import ghidra.util.task.ConsoleTaskMonitor
import ghistabs.diag.DummySink
import ghistabs.importer.StabOnlyAddressResolver
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Unit tests for Harvester.globalize() behavior.
 *
 * Verifies stabs-algo-audit.AC3.1: recursive type ID globalization,
 * terminal pass-through, and InlineDef side effects.
 *
 * Tests are pure unit tests (Kind 1): no Program/DataTypeManager/Listing,
 * only ConsoleTaskMonitor, DummySink, and constructed test data.
 */
class HarvesterGlobalizeTest {
    private fun createTestHarvester(records: List<StabRecord> = emptyList()): Harvester {
        val harvester = Harvester(
            monitor = ConsoleTaskMonitor(),
            sink = DummySink,
            resolver = StabOnlyAddressResolver(),
        )
        harvester.preSeedHeaders(records)
        return harvester
    }

    /**
     * Test: Identity on terminal types (Complex, XRef, Enum, Builtin, Void).
     *
     * Terminal nodes pass through unchanged (no LocalTypeId references).
     * Source: stabs-canonicalization.md §5 — terminal nodes pass through unchanged.
     */
    @Test
    fun testGlobalizeTerminalTypes() {
        val harvester = createTestHarvester(records = listOf())

        // TypeDecl.Complex: terminal
        val complex = TypeDecl.Complex<LocalTypeId>(rCode = 3, sizeBytes = 128)
        val globalizedComplex = harvester.globalize(complex)
        assertEquals(complex, globalizedComplex)

        // TypeDecl.Enum: terminal
        val enumType = TypeDecl.Enum<LocalTypeId>(members = listOf("A" to 0L, "B" to 1L))
        val globalizedEnum = harvester.globalize(enumType)
        assertEquals(enumType, globalizedEnum)

        // TypeDecl.XRef: terminal
        val xref = TypeDecl.XRef<LocalTypeId>(kind = AggrKind.STRUCT, tagName = "Foo")
        val globalizedXref = harvester.globalize(xref)
        assertEquals(xref, globalizedXref)
    }

    /**
     * Test: Pointer globalizes its referent.
     *
     * Input: Pointer(Ref(LocalTypeId(0, 5)))
     * Expected: Pointer(Ref(GlobalTypeId(CUSource("cu.c"), 5)))
     * Source: stabs-canonicalization.md §5 — recursive types descend into children.
     */
    @Test
    fun testGlobalizePointer() {
        val cuName = "cu.c"
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

        val input = TypeDecl.Pointer(
            pointee = TypeDecl.Ref(LocalTypeId(0, 5)),
        )
        val result = harvester.globalize(input)

        val expected = TypeDecl.Pointer(
            pointee = TypeDecl.Ref(GlobalTypeId(SourceFile.CUSource(cuName), 5)),
        )
        assertEquals(expected, result)
    }

    /**
     * Test: Array globalizes element, length, and index types.
     *
     * Input: Array(element=Ref(LocalTypeId(0,3)), length=10, indexType=Ref(LocalTypeId(0,4)))
     * Expected: Array(element=Ref(GlobalTypeId(...,3)), length=10, indexType=Ref(GlobalTypeId(...,4)))
     */
    @Test
    fun testGlobalizeArray() {
        val cuName = "cu.c"
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

        val input = TypeDecl.Array(
            element = TypeDecl.Ref(LocalTypeId(0, 3)),
            length = 10L,
            indexType = TypeDecl.Ref(LocalTypeId(0, 4)),
        )
        val result = harvester.globalize(input)

        val expected = TypeDecl.Array(
            element = TypeDecl.Ref(GlobalTypeId(SourceFile.CUSource(cuName), 3)),
            length = 10L,
            indexType = TypeDecl.Ref(GlobalTypeId(SourceFile.CUSource(cuName), 4)),
        )
        assertEquals(expected, result)
    }

    /**
     * Test: Struct globalizes field types recursively.
     *
     * A struct with two fields, each containing a LocalTypeId reference.
     * Both field types should be globalized.
     */
    @Test
    fun testGlobalizeStruct() {
        val cuName = "cu.c"
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

        val input = TypeDecl.Struct(
            kind = AggrKind.STRUCT,
            sizeBytes = 8L,
            bases = emptyList(),
            fields = listOf(
                FieldDecl(
                    name = "x",
                    type = TypeDecl.Ref(LocalTypeId(0, 1)),
                    offsetBits = 0L,
                    sizeBits = 32L,
                    isStatic = false,
                ),
                FieldDecl(
                    name = "y",
                    type = TypeDecl.Ref(LocalTypeId(0, 2)),
                    offsetBits = 32L,
                    sizeBits = 32L,
                    isStatic = false,
                ),
            ),
            methods = emptyList(),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )
        val result = harvester.globalize(input)

        val globalCuSource = SourceFile.CUSource(cuName)
        val expected = TypeDecl.Struct(
            kind = AggrKind.STRUCT,
            sizeBytes = 8L,
            bases = emptyList(),
            fields = listOf(
                FieldDecl(
                    name = "x",
                    type = TypeDecl.Ref(GlobalTypeId(globalCuSource, 1)),
                    offsetBits = 0L,
                    sizeBits = 32L,
                    isStatic = false,
                ),
                FieldDecl(
                    name = "y",
                    type = TypeDecl.Ref(GlobalTypeId(globalCuSource, 2)),
                    offsetBits = 32L,
                    sizeBits = 32L,
                    isStatic = false,
                ),
            ),
            methods = emptyList(),
            hasVTablePointerMarker = false,
            vtableTargetTypeId = null,
        )
        assertEquals(expected, result)
    }

    /**
     * Test: InlineDef produces TypeAst as side effect via walkDefinitions.
     *
     * When globalize() encounters an InlineDef, its body is globalized.
     * walkDefinitions() should return the emitted TypeAst.
     * Source: stabs-canonicalization.md §5 — InlineDef side-effect.
     */
    @Test
    fun testGlobalizeInlineDefWithWalkDefinitions() {
        val cuName = "cu.c"
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

        val inlineDefId = LocalTypeId(0, 7)
        val input = TypeDecl.InlineDef(
            id = inlineDefId,
            body = TypeDecl.Struct(
                kind = AggrKind.STRUCT,
                sizeBytes = 4L,
                bases = emptyList(),
                fields = listOf(
                    FieldDecl(
                        name = "field",
                        type = TypeDecl.Ref(LocalTypeId(0, 1)),
                        offsetBits = 0L,
                        sizeBits = 32L,
                        isStatic = false,
                    ),
                ),
                methods = emptyList(),
                hasVTablePointerMarker = false,
                vtableTargetTypeId = null,
            ),
        )

        // Globalize the InlineDef
        val result = harvester.globalize(input)

        // walkDefinitions should extract the emitted TypeAst
        val asts = harvester.walkDefinitions(result)

        assertEquals(1, asts.size, "walkDefinitions should return exactly one TypeAst from InlineDef")
        val ast = asts[0]
        assertEquals(GlobalTypeId(SourceFile.CUSource(cuName), 7), ast.id)
        assertEquals(cuName, ast.cu.filename)
    }

    /**
     * Test: Ref with file=0 maps to CUSource.
     *
     * Input: Ref(LocalTypeId(0, 5)) in context of CU "cu.c"
     * Expected: Ref(GlobalTypeId(CUSource("cu.c"), 5))
     * Source: stabs-canonicalization.md §5 — file=0 → CUSource.
     */
    @Test
    fun testGlobalizeRefFile0() {
        val cuName = "cu.c"
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

        val input = TypeDecl.Ref(LocalTypeId(0, 5))
        val result = harvester.globalize(input)

        val expected = TypeDecl.Ref(GlobalTypeId(SourceFile.CUSource(cuName), 5))
        assertEquals(expected, result)
    }

    /**
     * Test: Ref through HeaderSource.
     *
     * Setup: CU processes BINCL record for a header, allocating fileNum 1.
     * Input: Ref(LocalTypeId(1, 3)) → references type 3 in the header.
     * Expected: Ref(GlobalTypeId(HeaderSource(headerFile), 3))
     * Source: stabs-canonicalization.md §3, §5.
     */
    @Test
    fun testGlobalizeRefThroughHeader() {
        val cuName = "cu.c"
        val headerName = "header.h"
        val headerChecksum = 0x12345678L

        // Records to establish BINCL context
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
            StabRecord(
                recordIndex = 1,
                type = StabType.N_BINCL,
                rawType = 0x82,
                other = 0,
                desc = 0,
                value = headerChecksum,
                name = headerName,
            ),
        )
        val harvester = createTestHarvester(records = records)

        // Now globalize a Ref to file 1 (the header)
        val input = TypeDecl.Ref(LocalTypeId(1, 3))
        val result = harvester.globalize(input)

        // The result should have a GlobalTypeId with a HeaderSource
        val resultRef = result as TypeDecl.Ref<GlobalTypeId>
        val resultId = resultRef.id
        assertTrue(resultId.source is SourceFile.HeaderSource, "Expected HeaderSource, got ${resultId.source}")
        assertEquals(3, resultId.n)
    }
}
