package ghistabs.hierarchy

import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.VoidDataType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.entrypoints.GccVftableAnalyzer
import ghistabs.hierarchy.ClassHierarchy.Origin
import ghistabs.parse.Access
import ghistabs.runTransaction
import ghistabs.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * Classes no stabs describe, swept by [GccVftableAnalyzer], with hand-built Itanium typeinfo:
 *
 * ```
 * struct Foo { virtual void f() = 0; };                // __class_type_info
 * struct Bar : Foo { void f(); };                      // __si_class_type_info
 * struct Baz : virtual Foo, private Bar { void f(); }; // __vmi_class_type_info
 * struct Qux { virtual void f(); };                    // no typeinfo (-fno-rtti)
 * ```
 */
@Tag("integration")
class SweptClassHierarchyIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program get() = builder.program

    private fun hex(v: Int) = "0x${v.toString(16)}"
    private fun le(v: Int) = byteArrayOf(v.toByte(), (v shr 8).toByte(), (v shr 16).toByte(), (v shr 24).toByte())

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("swept-hierarchy", ProgramBuilder._X86, "gcc", this)
        builder.setExecute(builder.createMemory(".text", "0x402000", 0x100), true)
        builder.createEmptyFunction("__cxa_pure_virtual", "0x402000", 1, VoidDataType.dataType)
        builder.createEmptyFunction("_ZN3Bar1fEv", "0x402010", 1, VoidDataType.dataType)
        builder.createEmptyFunction("_ZN3Baz1fEv", "0x402020", 1, VoidDataType.dataType)
        builder.createEmptyFunction("_ZN3Qux1fEv", "0x402030", 1, VoidDataType.dataType)
        builder.createMemory(".rodata", "0x401000", 0x400)

        // The three __cxxabiv1 vtables a typeinfo's first word points into, two words past the label.
        val (cls, si, vmi) = listOf(0x401000, 0x401010, 0x401020)
        builder.createLabel(hex(cls), "_ZTVN10__cxxabiv117__class_type_infoE")
        builder.createLabel(hex(si), "_ZTVN10__cxxabiv120__si_class_type_infoE")
        builder.createLabel(hex(vmi), "_ZTVN10__cxxabiv121__vmi_class_type_infoE")

        val (foo, bar, baz) = listOf(0x401100, 0x401110, 0x401120)
        builder.setBytes(hex(foo), le(cls + 8) + le(0))
        builder.setBytes(hex(bar), le(si + 8) + le(0) + le(foo))
        // __flags, __base_count, then {base, offset_flags}: Foo virtual public, Bar private at +4.
        builder.setBytes(
            hex(baz),
            le(vmi + 8) + le(0) + le(0) + le(2) + le(foo) + le(-12 shl 8 or 3) + le(bar) + le(4 shl 8),
        )
        builder.createLabel(hex(foo), "_ZTI3Foo")
        builder.createLabel(hex(bar), "_ZTI3Bar")
        builder.createLabel(hex(baz), "_ZTI3Baz")

        for ((i, cls) in listOf(
            Triple("Foo", foo, 0x402000),
            Triple("Bar", bar, 0x402010),
            Triple("Baz", baz, 0x402020),
            Triple("Qux", 0, 0x402030),
        ).withIndex()) {
            val ztv = 0x401200 + i * 0x20
            builder.setBytes(hex(ztv), le(0) + le(cls.second) + le(cls.third) + le(0))
            builder.createLabel(hex(ztv), "_ZTV${cls.first.length}${cls.first}")
        }
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    @Test
    fun `a swept class takes its bases from its typeinfo`() {
        program.runTransaction("sweep") {
            GccVftableAnalyzer().added(program, program.memory, TaskMonitor.DUMMY, MessageLog())
        }
        val hierarchy = ClassHierarchy.of(program)
        fun cls(name: String) = hierarchy.classes.single { it.qualifiedName == name }
        fun bases(name: String) = cls(name).bases.map { Triple(it.target?.qualifiedName, it.isVirtual, it.access) }

        for (name in listOf("Foo", "Bar", "Baz")) cls(name).origin mustBe Origin.SWEPT_RTTI
        bases("Foo") mustBe emptyList()
        bases("Bar") mustBe listOf(Triple("Foo", false, Access.PUBLIC))
        bases("Baz") mustBe listOf(Triple("Foo", true, Access.PUBLIC), Triple("Bar", false, Access.PRIVATE))
        cls("Foo").isAbstract.mustBeTrue("Foo's slot is __cxa_pure_virtual")
        cls("Bar").isAbstract.mustBeFalse()

        cls("Qux").origin mustBe Origin.SWEPT
        cls("Qux").bases.mustBeEmpty()
    }
}
