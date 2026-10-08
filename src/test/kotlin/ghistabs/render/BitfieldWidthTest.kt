package ghistabs.render

import ghistabs.harvest.NameBinding
import ghistabs.harvest.Type
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.Globalizer
import ghistabs.parse.LocalTypeId
import ghistabs.parse.Parser
import ghistabs.parse.SourceFile
import ghistabs.parse.SymbolDecl
import ghistabs.parse.TypeDecl
import ghistabs.parse.TypeNameKind
import ghistabs.parse.globalize
import ghistabs.parse.mustBeOk
import ghistabs.test.*
import org.junit.jupiter.api.Test

/** [bitfieldWidth] over `hello.cc`'s `struct Flags { unsigned ro : 1, hidden : 1, mode : 3; signed prio : 4; }`. */
class BitfieldWidthTest {
    private val cu = SourceFile.CUSource("hello.cc")
    private val globalizer = object : Globalizer {
        override fun globalIdFor(id: LocalTypeId) = GlobalTypeId(cu, id.n)
    }

    private fun widths(stab: String, vararg types: Type): Map<String, Long?> {
        val sym = Parser(stab).parseSymbol().mustBeOk() as SymbolDecl.NamedType
        val body = sym.type.globalize(globalizer) as TypeDecl.Aggregate
        val graph = typesOf(*types)
        return body.fields.associate { it.name to graph.bitfieldWidth(it) }
    }

    private fun named(name: String, n: Int, min: Long, max: Long) =
        GlobalTypeId(cu, n).let { Type(cu, it, NameBinding(name, TypeNameKind.TYPEDEF), longRange(it, min, max)) }

    private fun int(n: Int) = named("int", n, -2147483648, 2147483647)

    /** The harvest registers a type defined inline at its first use; later fields name it by id. */
    private fun unsigned(n: Int) = named("unsigned int", n, 0, 4294967295)

    /** gcc 12 (`hello_elf_gcc12`), whose `int` is `(0,9)`, defined before `Flags`. */
    @Test
    fun `gcc 12 bitfields carry their bitsize`() {
        widths(
            "Flags:Tt(0,11)=s4ro:(0,37)=r(0,37);0;037777777777;,0,1;hidden:(0,37),1,1;mode:(0,37),2,3;prio:(0,9),5,4;;",
            int(9),
            unsigned(37),
        ) mustBe mapOf("ro" to 1L, "hidden" to 1L, "mode" to 3L, "prio" to 4L)
    }

    /** winnt.h's `_LDT_ENTRY.HighWord.Bits`: an 8-bit field of a 32-bit DWORD on a byte boundary. */
    @Test
    fun `a byte-aligned field narrower than its type is a bitfield`() {
        widths("Bits:T(0,1)=s4BaseMid:(0,2)=r(0,2);0;037777777777;,0,8;Type:(0,2),8,5;;", unsigned(2)) mustBe
            mapOf("BaseMid" to 8L, "Type" to 5L)
    }

    @Test
    fun `a field as wide as its type is not a bitfield`() {
        widths("Point:T(0,1)=s8x:(0,9),0,32;y:(0,9),32,32;;", int(9)) mustBe mapOf("x" to null, "y" to null)
    }
}
