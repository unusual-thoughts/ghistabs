package ghicpp.stl

import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.Composite
import ghidra.program.model.data.DataTypePath
import ghidra.program.model.data.Structure
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

/**
 * Every bundled layout builds, on whichever Ghidra the tests run against, to the sizes the PDB gave
 * its types: `std::string` in each runtime, and every struct the size its file says.
 */
class StlLayoutsTest {
    @Test
    fun `std string is the size each runtime makes it`() {
        mapOf(
            "msvcp90_x86" to 28,
            "msvcp90_x64" to 40,
            "msvcp140_x86" to 24,
            "msvcp140_x64" to 32,
            "msvcp140d_x86" to 28,
            "msvcp140d_x64" to 40,
        ).forEach { (name, size) ->
            StlLayouts.load(name)[DataTypePath(CategoryPath("/std"), STRING)]?.length mustBe size
        }
    }

    @Test
    fun `every bundled struct builds to its size, with its members`() {
        MsvcRuntime.BUNDLED.forEach { name ->
            val types = StlLayouts.load(name).all()
            val structs = types.filterIsInstance<Structure>().filter { !it.isNotYetDefined }
            (structs.size > 100) mustBe true
            val text = StlLayouts::class.java.getResourceAsStream("/ghicpp/stl/$name.txt")!!
                .use { it.readBytes().toString(Charsets.UTF_8) }
            val sizes = text.lineSequence().filter { it.startsWith("S\t") }
                .associate { it.split('\t').let { (_, path, length) -> path to length.toInt() } }
            structs.forEach { s -> s.length mustBe sizes.getValue(s.pathName) }
            types.filterIsInstance<Composite>().forEach { c ->
                c.definedComponents.forEach { m -> (m.dataType.length > 0 || m.length == 0) mustBe true }
            }
        }
    }

    companion object {
        const val STRING = "basic_string<char,std::char_traits<char>,std::allocator<char>_>"
    }
}
