package ghicpp.stl

import ghidra.app.cmd.label.DemanglerCmd
import ghidra.app.util.demangler.DemanglerOptions
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * A `std::string` constructor imported from the runtime, demangled with its signature: its `this` starts out
 * as the demangler's empty placeholder and ends as the runtime's `basic_string`.
 */
@Tag("integration")
class MsvcStlApplierIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun `msvcp90 x86 string`() = check(
        ProgramBuilder._X86,
        "??0?\$basic_string@DU?\$char_traits@D@std@@V?\$allocator@D@2@@std@@QAE@PBD@Z",
        "msvcp90_x86",
        size = 28,
    )

    @Test
    fun `msvcp140 x64 string`() = check(
        ProgramBuilder._X64,
        "??0?\$basic_string@DU?\$char_traits@D@std@@V?\$allocator@D@2@@std@@QEAA@PEBD@Z",
        "msvcp140_x64",
        size = 32,
    )

    @Test
    fun `msvcp140d x86 string carries the container proxy`() = check(
        ProgramBuilder._X86,
        "??0?\$basic_string@DU?\$char_traits@D@std@@V?\$allocator@D@2@@std@@QAE@PBD@Z",
        "msvcp140d_x86",
        size = 28,
    )

    private fun check(language: String, mangled: String, layouts: String, size: Int) {
        val builder = ProgramBuilder("stl", language, "windows", this)
        try {
            builder.createMemory(".text", "0x10001000", 0x100)
            val fn = builder.createEmptyFunction(mangled, "0x10001000", 1, DataType.DEFAULT)
            val program = builder.program
            builder.withTransaction {
                val options = DemanglerOptions().apply { setApplySignature(true) }
                DemanglerCmd(fn.entryPoint, mangled, options).applyTo(program, TaskMonitor.DUMMY) mustBe true
            }
            placeholders(program) mustBe listOf("/Demangler/std/$STRING")

            builder.withTransaction { MsvcStlApplier(program, StlLayouts.load(layouts)).apply() }

            placeholders(program) mustBe emptyList()
            val self = (program.functionManager.getFunctionAt(fn.entryPoint).getParameter(0).dataType as Pointer)
                .dataType as Structure
            self.pathName mustBe "/std/$STRING"
            self.length mustBe size
        } finally {
            builder.dispose()
        }
    }

    private fun placeholders(program: Program) = program.dataTypeManager.allStructures.asSequence()
        .filter { it.isNotYetDefined && it.name.startsWith("basic_string<") }
        .map { it.pathName }.toList()

    companion object {
        const val STRING = "basic_string<char,std::char_traits<char>,std::allocator<char>_>"
    }
}
