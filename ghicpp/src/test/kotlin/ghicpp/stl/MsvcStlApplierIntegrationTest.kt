package ghicpp.stl

import ghicpp.Access
import ghicpp.ClassHierarchyRecords
import ghicpp.ClassHierarchyRecords.Companion.readClassRecord
import ghicpp.classStruct
import ghicpp.isKnownLayout
import ghicpp.sizeClassStruct
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
import ghidra.program.model.listing.GhidraClass
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

    /**
     * A class of the runtime's that the program has a class for, as its RTTI or the demangler leaves it: the
     * class passes take the archive's layout for its struct, as it is, and its bases come off the classes file.
     */
    @Test
    fun `a std class takes the archive layout and its bases off the runtime's PDB`() {
        val builder = ProgramBuilder("stl", ProgramBuilder._X64, "windows", this)
        try {
            builder.createMemory(".text", "0x140001000", 0x100)
            val program = builder.program
            lateinit var filebuf: GhidraClass
            lateinit var streambuf: GhidraClass
            lateinit var global: GhidraClass
            builder.withTransaction {
                val std = program.symbolTable.createNameSpace(null, "std", SourceType.IMPORTED)
                filebuf = program.symbolTable.createClass(std, FILEBUF, SourceType.IMPORTED)
                streambuf = program.symbolTable.createClass(std, STREAMBUF, SourceType.IMPORTED)
                global = program.symbolTable.createClass(null, "Probe", SourceType.IMPORTED)
            }
            // A placeholder for the class, so the applier resolves its layout.
            builder.withTransaction {
                program.dataTypeManager.addDataType(
                    StructureDataType(CategoryPath("/Demangler/std"), FILEBUF, 0),
                    DataTypeConflictHandler.DEFAULT_HANDLER,
                )
            }
            val classes = StdClass.parse(
                "C\t/std/$FILEBUF\n\tB\tpublic\t0\t/std/$STREAMBUF\nC\t/std/$STREAMBUF\n",
            )
            val archive = MsvcStlArchives.open("msvcp140_x64")
            try {
                lateinit var result: MsvcStlApplier.Result
                builder.withTransaction { result = MsvcStlApplier(program, archive, classes).apply() }
                result.recorded mustBe 2

                // A class in no namespace has no archive path, and nothing filed for it yet.
                program.classStruct(global) mustBe null
                val struct = program.classStruct(filebuf)!!
                struct.pathName mustBe "/std/$FILEBUF"
                struct.isKnownLayout() mustBe true
                // A class pass sizing it off its allocations leaves the runtime's layout as it is.
                builder.withTransaction { program.sizeClassStruct(filebuf, struct.length + 16) }
                program.classStruct(filebuf)!!.length mustBe struct.length

                val record = program.readClassRecord()!!
                record.getValue(filebuf.id) mustBe ClassHierarchyRecords.Entry(
                    program.dataTypeManager.getID(struct),
                    listOf(ClassHierarchyRecords.Base(streambuf.id, null, false, Access.PUBLIC, 0)),
                    "msvcp140_x64",
                )
                // Resolved along with the class deriving from it, and recorded as having no bases.
                record.getValue(streambuf.id).structId mustBe
                    program.dataTypeManager.getID(program.classStruct(streambuf)!!)
                record.getValue(streambuf.id).bases mustBe emptyList()
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
        const val FILEBUF = "basic_filebuf<char,std::char_traits<char>_>"
        const val STREAMBUF = "basic_streambuf<char,std::char_traits<char>_>"
    }
}
