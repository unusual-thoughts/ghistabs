package ghicpp.stl

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.DataTypePath
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * A `std::string` constructor imported from the runtime, as the demangler types it: its `this` starts out
 * as the demangler's empty placeholder and ends as the runtime's `basic_string`, linked to the archive.
 */
@Tag("integration")
class MsvcStlApplierIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun `msvcp90 x86 string`() = check(
        ProgramBuilder._X86,
        "msvcp90_x86",
        size = 28,
    )

    @Test
    fun `msvcp140 x64 string`() = check(
        ProgramBuilder._X64,
        "msvcp140_x64",
        size = 32,
    )

    @Test
    fun `msvcp140d x86 string carries the container proxy`() = check(
        ProgramBuilder._X86,
        "msvcp140d_x86",
        size = 28,
    )

    private fun check(language: String, archiveName: String, size: Int) {
        val builder = ProgramBuilder("stl", language, "windows", this)
        try {
            builder.createMemory(".text", "0x10001000", 0x100)
            val fn = builder.createEmptyFunction("ctor", "0x10001000", 1, DataType.DEFAULT)
            val program = builder.program
            // What the Microsoft demangler leaves for an imported method of the class: its `this`, a
            // pointer to an empty struct at the class's namespace path under /Demangler.
            builder.withTransaction {
                val placeholder = program.dataTypeManager.addDataType(
                    StructureDataType(CategoryPath("/Demangler/std"), STRING, 0),
                    DataTypeConflictHandler.DEFAULT_HANDLER,
                )
                val self = ParameterImpl("this", PointerDataType(placeholder), program)
                fn.replaceParameters(
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true,
                    SourceType.IMPORTED,
                    self,
                )
            }
            placeholders(program) mustBe listOf("/Demangler/std/$STRING")

            val archive = MsvcStlArchives.open(archiveName)
            try {
                builder.withTransaction { MsvcStlApplier(program, archive).apply() }

                placeholders(program) mustBe emptyList()
                val self = program.functionManager.getFunctionAt(fn.entryPoint).getParameter(0).dataType
                    .let { (it as Pointer).dataType as Structure }
                self.pathName mustBe "/std/$STRING"
                self.length mustBe size
                // Linked to the archive it came from, not a copy.
                self.sourceArchive.sourceArchiveID mustBe archive.universalID
                self.sourceArchive.name mustBe archiveName
            } finally {
                archive.close()
            }
        } finally {
            builder.dispose()
        }
    }

    private fun placeholders(program: Program) = program.dataTypeManager.allStructures.asSequence()
        .filter { it.isNotYetDefined && it.name.startsWith("basic_string<") }
        .map { it.pathName }.toList()

    @Test
    fun `every bundled archive opens, with std string the size its runtime makes it`() {
        mapOf(
            "msvcp90_x86" to 28,
            "msvcp90_x64" to 40,
            "msvcp140_x86" to 24,
            "msvcp140_x64" to 32,
            "msvcp140d_x86" to 28,
            "msvcp140d_x64" to 40,
        ).forEach { (name, size) ->
            val archive = MsvcStlArchives.open(name)
            try {
                archive.getDataType(DataTypePath(CategoryPath("/std"), STRING))?.length mustBe size
            } finally {
                archive.close()
            }
        }
    }

    companion object {
        const val STRING = "basic_string<char,std::char_traits<char>,std::allocator<char>_>"
    }
}
