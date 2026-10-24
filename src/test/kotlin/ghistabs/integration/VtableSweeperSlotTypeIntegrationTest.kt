package ghistabs.integration

import ghidra.app.util.demangler.DemangledFunction
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.EnumDataType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.Demangler
import ghistabs.formals
import ghistabs.runTransaction
import ghistabs.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * A swept slot whose target has no function is typed off its linkage name. gcc 3's stabs file
 * `std::_Ios_Openmode` under no namespace, so the type is ours under its CU's category, never
 * `/std`, where Ghidra's own lookup goes.
 */
@Tag("integration")
class VtableSweeperSlotTypeIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private val builder = ProgramBuilder("test", ProgramBuilder._X86)

    @AfterEach
    fun tearDown() = builder.dispose()

    @Test
    fun `a demangled slot parameter takes the type the stabs made under no namespace`() {
        val program = builder.program
        val ctx = program.defaultContext()
        val registry = ctx.defaultTypeRegistry()
        val openmode = program.runTransaction("seed") {
            registry.register(EnumDataType(CategoryPath("/ios_init.cc"), "_Ios_Openmode", 4))
        }
        val seekoff = Demangler.of(
            "_ZNSt15basic_streambufIcSt11char_traitsIcEE7seekoffExSt12_Ios_SeekdirSt13_Ios_Openmode",
        ) as DemangledFunction

        val typed = with(ctx.vtableSweeper(registry)) {
            seekoff.formals.last().slotParameterType("vftable-demangled-untyped", "seekoff")
        }

        typed mustBeSameAs openmode
        ctx.diagnostics.degradationTargets()["vftable-demangled-untyped"].orEmpty() mustBe emptyList()
    }
}
