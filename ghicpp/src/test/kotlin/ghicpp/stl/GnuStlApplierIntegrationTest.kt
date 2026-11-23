package ghicpp.stl

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.ComponentOffsetSettingsDefinition
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.data.TypeDef
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidrakt.Demangler
import ghidrakt.demanglerPath
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * A libstdc++ method as the GNU demangler types it: its `this` starts out as the demangler's empty
 * placeholder and ends as the archive's class, in whichever string ABI the mangled name says.
 */
@Tag("integration")
class GnuStlApplierIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun `the C++11 ABI's string`() = check(
        ProgramBuilder._X64,
        "libstdcxx_x64",
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7reserveEm",
        "/std/__cxx11/basic_string<char,_std::char_traits<char>,_std::allocator<char>_>",
        32,
    )

    @Test
    fun `the copy-on-write string`() = check(
        ProgramBuilder._X86,
        "libstdcxx_x86",
        "_ZNSs7reserveEj",
        "/std/basic_string<char,_std::char_traits<char>,_std::allocator<char>_>",
        4,
        shift = 12,
    )

    @Test
    fun `a container the demangler spells otherwise than the DWARF`() = check(
        ProgramBuilder._X64,
        "libstdcxx_x64",
        "_ZNSt3mapIiiSt4lessIiESaISt4pairIKiiEEE5clearEv",
        "/std/map<int,_int,_std::less<int>,_std::allocator<std::pair<int_const,_int>_>_>",
        48,
    )

    @Test
    fun `MinGW's wide string, whose wchar_t is two bytes`() = check(
        ProgramBuilder._X64,
        "libstdcxx_mingw_x64",
        "_ZNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEE7reserveEy",
        "/std/__cxx11/basic_string<wchar_t,_std::char_traits<wchar_t>,_std::allocator<wchar_t>_>",
        32,
    )

    /**
     * [shift]: a copy-on-write string's `_M_p` points [shift] bytes into `_Rep_chars`, past the header, so
     * the decompiler reaches the header's fields through it.
     */
    private fun check(
        language: String,
        archiveName: String,
        mangled: String,
        path: String,
        size: Int,
        shift: Long? = null,
    ) {
        val builder = ProgramBuilder("stl", language, "gcc", this)
        try {
            builder.createMemory(".text", "0x401000", 0x100)
            val fn = builder.createEmptyFunction(mangled, "0x401000", 1, DataType.DEFAULT)
            val program = builder.program
            // What the demangler leaves for the method: its `this`, a pointer to an empty struct at the
            // class's namespace path under /Demangler, spelled as the demangler spells it.
            val cls = checkNotNull(Demangler.of(mangled)?.namespace) { "cannot demangle $mangled" }
            builder.withTransaction {
                val placeholder = program.dataTypeManager.addDataType(
                    StructureDataType(cls.demanglerPath.parent, cls.demanglerPath.name, 0),
                    DataTypeConflictHandler.DEFAULT_HANDLER,
                )
                fn.replaceParameters(
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true,
                    SourceType.IMPORTED,
                    ParameterImpl("this", PointerDataType(placeholder), program),
                )
            }
            placeholders(program).size mustBe 1

            GnuRuntime.ARCHIVES.open(archiveName).use { opened ->
                val archive = opened.dataTypeManager
                builder.withTransaction {
                    StlApplier(program, archive, roots = StlApplier.GNU_ROOTS).apply()
                }
                placeholders(program) mustBe emptyList()
                val self = program.functionManager.getFunctionAt(fn.entryPoint).getParameter(0).dataType
                    .let { (it as Pointer).dataType as Structure }
                self.pathName mustBe path
                self.length mustBe size
                self.sourceArchive.name mustBe archiveName
                if (shift != null) {
                    val hider = self.getComponent(0).dataType as Structure
                    val p = hider.getComponent(0).dataType as TypeDef
                    p.name mustBe "_Rep_chars_ptr"
                    ComponentOffsetSettingsDefinition.DEF.getValue(p.defaultSettings) mustBe shift
                    val chars = (p.baseDataType as Pointer).dataType as Structure
                    chars.name mustBe "_Rep_chars"
                    chars.getComponentAt(shift.toInt()).fieldName mustBe "_M_data"
                }
            }
        } finally {
            builder.dispose()
        }
    }

    private fun placeholders(program: Program) = program.dataTypeManager.allStructures.asSequence()
        .filter { it.isNotYetDefined && it.categoryPath.path.startsWith("/Demangler") }
        .map { it.pathName }.toList()
}
