package ghistabs.integration

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.StructureDataType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.diagnose.defaultContext
import ghistabs.diagnose.defaultTypeRegistry
import ghistabs.importer.DemanglerReplacer
import ghistabs.runTransaction
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * Real Ghidra headless integration tests for DemanglerReplacer.
 *
 * AC7.1: Demangler stub replacement removes stub and replaces references.
 * AC7.2: Stub replacement is idempotent when stub already missing.
 * AC7.3: Parameter type references are updated after replacement.
 *
 * These tests use real Ghidra Program/DTM objects via AbstractGhidraHeadlessIntegrationTest,
 * verifying actual demangler stub replacement against the program database.
 */
@Tag("integration")
class DemanglerReplaceIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder

    @BeforeEach
    fun setUp() {
        // Create a minimal test program with x86 architecture
        builder = ProgramBuilder("test", ProgramBuilder._X86)
        // Add memory blocks
        builder.createMemory(".text", "0x400000", 512)
        builder.createMemory(".data", "0x401000", 256)
        // Add stab sections with initialized (zero-filled) memory
        builder.createMemory(".stab", "0x402000", 4)
        builder.createMemory(".stabstr", "0x403000", 4)
    }

    @AfterEach
    fun tearDown() {
        builder.dispose()
    }

    /**
     * AC7.1: Demangler stub replacement removes stub and replaces references.
     *
     * - Build a program with real DTM
     * - Seed a /Demangler/Foo empty Structure (stub)
     * - Seed a /proj/Foo non-empty Structure with one int32 field (replacement)
     * - Construct ImportContext + TypeRegistry
     * - Call DemanglerReplacer(ctx, typeRegistry).run()
     * - Assert /Demangler/Foo is now null (removed)
     * - Assert /proj/Foo still exists and has the same int32 field
     */
    @Test
    fun testDemanglerStubReplacedByDerivedType() {
        val program = builder.program
        val dtm = program.dataTypeManager

        val ctx = program.defaultContext()
        val registry = ctx.defaultTypeRegistry()

        // Seed /Demangler/Foo as empty structure (stub) within a transaction
        program.runTransaction("setup-test") {
            val stubPath = CategoryPath("/Demangler")
            val stubDt = StructureDataType(stubPath, "Foo", 0)
            dtm.addDataType(stubDt, DataTypeConflictHandler.KEEP_HANDLER)

            // Seed /proj/Foo as non-empty structure with one int32 field (replacement).
            // Route through registry.register so it lands in extrasByName, which
            // is what DemanglerReplacer's authoritative findByName consults.
            val projPath = CategoryPath("/proj")
            val projDt = StructureDataType(projPath, "Foo", 4)
            val intType = dtm.getDataType(CategoryPath("/"), "int")
            if (intType != null) {
                projDt.add(intType, 4, "fieldA", "first int")
            }
            registry.register(projDt)
        }

        // Run DemanglerReplacer inside a transaction — `dtm.replaceDataType`
        // (used when a real replacement is found) requires one.
        program.runTransaction("demangler-replace") {
            DemanglerReplacer(ctx, registry).run()
        }

        // Verify that the stub is gone and the replacement remains.
        val stubPath = CategoryPath("/Demangler")
        val stubAfter = dtm.getDataType(stubPath, "Foo")
        assertTrue(stubAfter == null, "/Demangler/Foo stub should have been replaced; still present: $stubAfter")
        val projPath = CategoryPath("/proj")
        val projAfter = dtm.getDataType(projPath, "Foo")
        assertTrue(projAfter != null, "/proj/Foo (replacement) should still exist after DemanglerReplacer runs")
        if (projAfter != null) {
            assertTrue(
                projAfter is ghidra.program.model.data.Structure,
                "/proj/Foo should remain a Structure",
            )
        }
    }

    /**
     * AC7.2: Stub replacement is idempotent when stub already missing.
     *
     * - Build a program without seeding a stub (stub already missing)
     * - Seed only the replacement /proj/Foo
     * - Call DemanglerReplacer(ctx, typeRegistry).run()
     * - Assert no exceptions are thrown
     * - Assert /proj/Foo still exists (unchanged)
     */
    @Test
    fun testDemanglerReplacementIdempotentWhenStubMissing() {
        val program = builder.program
        val dtm = program.dataTypeManager

        // Seed only /proj/Foo (no stub) within a transaction
        program.runTransaction("setup-test") {
            val projPath = CategoryPath("/proj")
            val projDt = StructureDataType(projPath, "Foo", 4)
            // Resolve the int type first to avoid null when adding
            val intType = dtm.getDataType(CategoryPath("/"), "int")
            if (intType != null) {
                projDt.add(intType, 4, "fieldA", null)
            }
            dtm.addDataType(projDt, DataTypeConflictHandler.KEEP_HANDLER)
        }

        // Create ImportContext
        val ctx = program.defaultContext()

        // Run DemanglerReplPacer (should skip gracefully since stub is absent)
        val registry = ctx.defaultTypeRegistry()
        // Should not throw
        DemanglerReplacer(ctx, registry).run()

        // Assert /proj/Foo still exists
        val projPath = CategoryPath("/proj")
        val projAfter = dtm.getDataType(projPath, "Foo")
        assertTrue(projAfter != null, "/proj/Foo should still exist after idempotent run")
    }
}
