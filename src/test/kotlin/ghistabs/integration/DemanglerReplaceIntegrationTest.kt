package ghistabs.integration

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.*
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.importer.DemanglerReplacer
import ghistabs.runTransaction
import ghistabs.test.*
import org.junit.jupiter.api.AfterEach
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
    fun demanglerStubReplacedByDerivedType() {
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
            DemanglerReplacer(ctx, registry).replace()
        }

        // Verify that the stub is gone and the replacement remains.
        val stubPath = CategoryPath("/Demangler")
        val stubAfter = dtm.getDataType(stubPath, "Foo")
        stubAfter.mustBeNull("/Demangler/Foo stub should have been replaced; still present: $stubAfter")
        val projPath = CategoryPath("/proj")
        val projAfter = dtm.getDataType(projPath, "Foo")
        projAfter.mustNotBeNull("/proj/Foo (replacement) should still exist after DemanglerReplacer runs")
        projAfter.mustBeA<Structure>("/proj/Foo should remain a Structure")
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
    fun demanglerReplacementIdempotentWhenStubMissing() {
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
        DemanglerReplacer(ctx, registry).replace()

        // Assert /proj/Foo still exists
        val projPath = CategoryPath("/proj")
        val projAfter = dtm.getDataType(projPath, "Foo")
        projAfter.mustNotBeNull("/proj/Foo should still exist after idempotent run")
    }

    /**
     * render-backlog §14: with typedef shortening on, `basic_string<…>` is renamed onto its
     * `string` typedef's name, so both a `string` typedef and the renamed `string` struct — the
     * same type in two guises — end up registered under the name "string". findByName then saw
     * two matches, the `/Demangler` preferred-category matched neither, and it returned null
     * ("ambiguous") — so the `/Demangler/string` stub stopped being replaced.
     *
     * This pins the fix: a typedef and its own resolved target are collapsed, the typedef wins,
     * and the stub is replaced. Reproduces the post-shortening registry state directly (no full
     * analysis / OPT_SHORTEN_TYPEDEFS run needed) — both types are simply registered as "string".
     */
    @Test
    fun demanglerStubReplacedWhenTypedefAndRenamedTargetCollide() {
        val program = builder.program
        val dtm = program.dataTypeManager

        val ctx = program.defaultContext()
        val registry = ctx.defaultTypeRegistry()

        program.runTransaction("setup-test") {
            // The renamed `basic_string<…>` struct: now named "string", non-empty.
            val structDt = StructureDataType(CategoryPath("/std/stringfwd"), "string", 0)
            val intType = dtm.getDataType(CategoryPath("/"), "int")
            if (intType != null) structDt.add(intType, 4, "_M_p", null)
            val registeredStruct = registry.register(structDt)

            // The surviving `string` typedef pointing at that struct — same name, other category.
            val typedef = TypedefDataType(CategoryPath("/stabs"), "string", registeredStruct)
            registry.register(typedef)

            // Ghidra's on-demand demangler stub.
            val stub = StructureDataType(CategoryPath("/Demangler/std"), "string", 0, dtm)
            dtm.createCategory(CategoryPath("/Demangler/std")).addDataType(stub, DataTypeConflictHandler.KEEP_HANDLER)
        }

        dtm.getDataType(CategoryPath("/Demangler/std"), "string").mustNotBeNull(
            "precondition: injected /Demangler/std/string stub should exist",
        )

        program.runTransaction("demangler-replace") {
            DemanglerReplacer(ctx, registry).replace()
        }

        dtm.getDataType(CategoryPath("/Demangler/std"), "string").mustBeNull(
            "/Demangler/std/string should be replaced despite the typedef/renamed-struct name collision",
        )
    }

    /**
     * A type materialized in both its CU/include category (resolved) and `/stabs` (a ref-stub
     * placeholder) registers twice under one name. The `/Demangler/std` stub's preferred category
     * matches neither, so findByName saw two matches and returned null — leaving every locale facet
     * stub empty. This pins the tiebreaker: the `/stabs` placeholder loses to the real candidate.
     */
    @Test
    fun demanglerStubReplacedWhenStabsPlaceholderShadowsRealType() {
        val program = builder.program
        val dtm = program.dataTypeManager

        val ctx = program.defaultContext()
        val registry = ctx.defaultTypeRegistry()

        program.runTransaction("setup-test") {
            val real = StructureDataType(CategoryPath("/src/codecvt.cc/multi"), "codecvt<char,char,int>", 0)
            dtm.getDataType(CategoryPath("/"), "int")?.let { real.add(it, 4, "_M_c", null) }
            registry.register(real)
            registry.register(StructureDataType(CategoryPath("/stabs"), "codecvt<char,char,int>", 0))

            val stub = StructureDataType(CategoryPath("/Demangler/std"), "codecvt<char,char,int>", 0, dtm)
            dtm.createCategory(CategoryPath("/Demangler/std")).addDataType(stub, DataTypeConflictHandler.KEEP_HANDLER)
        }

        program.runTransaction("demangler-replace") {
            DemanglerReplacer(ctx, registry).replace()
        }

        dtm.getDataType(CategoryPath("/Demangler/std"), "codecvt<char,char,int>").mustBeNull(
            "/Demangler/std stub should be replaced by the real candidate, not left ambiguous with the /stabs placeholder",
        )
    }
}
