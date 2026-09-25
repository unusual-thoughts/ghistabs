package ghistabs.render

import ghistabs.parse.GlobalTypeId
import ghistabs.parse.Globalizer
import ghistabs.parse.LocalTypeId
import ghistabs.parse.Parser
import ghistabs.parse.SourceFile
import ghistabs.parse.SymbolDecl
import ghistabs.parse.globalize
import ghistabs.parse.mustBeOk
import ghistabs.test.*
import org.junit.jupiter.api.Test

/**
 * [spell] against gcc 12's own stabs for declarators that only read inside out. Each string is one
 * declaration compiled alone (`gcc -gstabs+ -S`, x86-64), so every type it uses is defined inline and
 * no other type needs to be in the graph.
 *
 * gcc writes a plain function type as `f<return type>` with no parameters — only a method's `#` lists
 * them — so a declaration's parameter list comes back empty: `()`, "unspecified", which is all the stab
 * still knows.
 */
class TypeSpellingTest {
    private val cu = SourceFile.CUSource("d.c")
    private val globalizer = object : Globalizer {
        override fun globalIdFor(id: LocalTypeId) = GlobalTypeId(cu, id.n)
    }

    private fun declare(stab: String): String {
        val sym = Parser(stab).parseSymbol().mustBeOk() as SymbolDecl.Static
        return sym.type.globalize(globalizer).spell(sym.name, typesOf(), null)
    }

    @Test
    fun `an array of pointers to functions returning pointers to arrays`() {
        declare(
            "x:G(0,1)=ar(0,2)=@s64;r(0,2);0;01777777777777777777777;;0;00000000000000000000002;(0,3)=*(0,4)=" +
                "f(0,5)=*(0,6)=ar(0,2);0;00000000000000000000004;(0,7)=r(0,7);0;127;",
        ) mustBe "char (*(*x[3])())[5]"
    }

    @Test
    fun `a pointer to a function returning a pointer to an array`() {
        // int (*(*foo)(const void *))[3]
        declare(
            "foo:G(0,1)=*(0,2)=f(0,3)=*(0,4)=ar(0,5)=@s64;r(0,5);0;01777777777777777777777;;0;" +
                "00000000000000000000002;(0,6)=r(0,6);-2147483648;2147483647;",
        ) mustBe "int (*(*foo)())[3]"
    }

    @Test
    fun `a const pointer to a function keeps its qualifier inside the parentheses`() {
        // int (* const bar)(char * const (*[5])(int , char ))
        declare("bar:G(0,1)=k(0,2)=*(0,3)=f(0,4)=r(0,4);-2147483648;2147483647;") mustBe "int (*const bar)()"
    }

    @Test
    fun `qualifiers sit to the right of what they qualify`() {
        // const char *const *pp
        declare("pp:G(0,1)=*(0,2)=k(0,3)=*(0,4)=k(0,5)=r(0,5);0;127;") mustBe "char const *const *pp"
        // volatile int *const vp
        declare("vp:G(0,1)=k(0,2)=*(0,3)=B(0,4)=r(0,4);-2147483648;2147483647;") mustBe "int volatile *const vp"
    }

    @Test
    fun `a pointer to an array needs parentheses, an array of pointers does not`() {
        declare(
            "ap:G(0,1)=*(0,2)=ar(0,3)=@s64;r(0,3);0;01777777777777777777777;;0;00000000000000000000003;" +
                "(0,4)=r(0,4);-2147483648;2147483647;",
        ) mustBe "int (*ap)[4]"
        declare(
            "arr:G(0,1)=ar(0,2)=@s64;r(0,2);0;01777777777777777777777;;0;00000000000000000000001;(0,3)=" +
                "ar(0,2);0;00000000000000000000002;(0,4)=*(0,5)=r(0,5);0;127;",
        ) mustBe "char *arr[2][3]"
    }

    @Test
    fun `a pointer to data member, in both gcc spellings`() {
        // gcc 12: the member type alone; gcc 2.95: a pointer to it. Both are `int A::*`.
        declare("pmi:G(0,1)=@(0,2)=xsA:,(0,3)=r(0,3);-2147483648;2147483647;") mustBe "int A::*pmi"
        declare("pmi:G(0,31)=*(0,32)=@(0,24)=xsA:,(0,1)=r(0,1);-2147483648;2147483647;") mustBe "int A::*pmi"
    }
}
