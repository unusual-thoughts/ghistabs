package ghistabs.integration

import ghidra.program.model.data.AbstractIntegerDataType
import ghidra.program.model.data.Composite
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.TypeDef
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.LoadedProgram
import ghistabs.entrypoints.StabsAnalyzer.Companion.import
import ghistabs.loadProgram
import ghistabs.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.io.File

/**
 * `features/ptrmem.cc` compiled and linked by both sides of gcc 3.4's change to pointers to data member:
 *
 *  - `ptrmem_elf_gcc295` (i386, potato) spells `int A::*` as `*@A,int` — a pointer to the offset
 *    type — and passes a copy-constructed class by invisible reference: as a `c:p` stack slot plus a
 *    `c:r` register home typed `C *`, or, to a `regparm` function, as `c:a…`.
 *  - `ptrmem_elf64_gcc12` (x86-64, bookworm) spells it `@A,int` alone, and writes that same
 *    by-value parameter as an explicit `&` reference instead.
 *
 * Both spellings must come out as one pointer-sized signed integer: the x86-64 build is the one
 * where materializing the member type (`int`) instead would be too narrow.
 */
@Tag("integration")
class MemberPointerIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram
    private val program get() = loaded.program
    private val pointerSize get() = program.dataTypeManager.dataOrganization.pointerSize

    private fun load(name: String) {
        assumeTrue(Fixtures.accepts(name), "excluded by -Pfixture")
        loaded = loadProgram(File("src/test/resources/binaries/features/$name"))
        program.defaultContext().import()
    }

    @AfterEach
    fun tearDown() {
        if (::loaded.isInitialized) loaded.close()
    }

    private fun DataType.stripTypedefs(): DataType = (this as? TypeDef)?.baseDataType?.stripTypedefs() ?: this

    private fun DataType.mustBeMemberPointer(what: String) = stripTypedefs().must(
        "$what should be a $pointerSize-byte signed integer, got ${this.pathName}",
    ) { this is AbstractIntegerDataType && isSigned && length == pointerSize }

    private fun global(name: String): DataType {
        val symbol = checkNotNull(program.symbolTable.getSymbols(name).firstOrNull()) { "no symbol $name" }
        return checkNotNull(program.listing.getDataAt(symbol.address)) { "$name not defined" }.dataType
    }

    @ParameterizedTest
    @ValueSource(strings = ["ptrmem_elf_gcc295", "ptrmem_elf64_gcc12"])
    fun `a pointer to data member is a pointer-sized offset`(fixture: String) {
        load(fixture)

        listOf("pmi", "pmd").forEach { global(it).mustBeMemberPointer(it) }

        // Only the pointer straight onto the member type is gcc ≤ 3.3's `int A::*`; through a typedef or a
        // qualifier it is a real pointer to one.
        for (name in listOf("ppm", "pcpm")) {
            val ptr = global(name).stripTypedefs()
            ptr.must("$name should be a pointer, got ${ptr.pathName}") { this is Pointer }
            (ptr as Pointer).dataType.mustBeMemberPointer("*$name")
        }

        val b = checkNotNull(
            program.dataTypeManager.allDataTypes.asSequence().filterIsInstance<Composite>().firstOrNull {
                it.name == "B"
            },
        ) { "struct B not materialized" }
        b.components.map { it.fieldName } mustBe listOf("f", "g")
        b.components.forEach { it.dataType.mustBeMemberPointer("B::${it.fieldName}") }
        b.length mustBe 2 * pointerSize
    }

    /**
     * gcc 2.95 only: gcc 12 writes the same parameter as an explicit `&`, which parsed as a reference
     * before invisible references were understood, so it would pass either way.
     */
    @Test
    fun `a class passed by invisible reference is a pointer parameter`() {
        load("ptrmem_elf_gcc295")

        // byval: the `c:p` stack slot + `c:r` home typed `C *`; byreg: `c:a`.
        for (fn in listOf("byval", "byreg")) {
            val func = checkNotNull(program.functionManager.getFunctions(true).firstOrNull { fn in it.name }) {
                "$fn not found"
            }
            func.getParameter(0).must("$fn's `c` should be the `C *` it holds, got ${func.signature}") {
                name == "c" && (dataType as? Pointer)?.dataType?.stripTypedefs()?.name == "C"
            }
        }
    }
}
