package ghistabs.parse

import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/** Pins the `static` the `S`/`V`/`f` stab letter spells: gcc's only record of internal linkage. */
class StorageClassTest {
    private fun storageClassOf(stab: String) =
        (Parser(stab).parseSymbol().mustBeOk() as SymbolDecl.Static<*>).scope.storageClass()

    @Test
    fun `file and function statics spell static, globals nothing`() {
        // hello.cc: `static Color g_color = GREEN;`, `static int calls;` in bump(), `long double g_ld = 1.5L;`
        storageClassOf("g_color:S(0,22)") mustBe "static "
        storageClassOf("calls:V(0,1)") mustBe "static "
        storageClassOf("g_ld:G(0,15)") mustBe ""
    }

    @Test
    fun `a file-static function spells static, a global one nothing`() {
        FunctionScope.FILE.storageClass() mustBe "static "
        FunctionScope.GLOBAL.storageClass() mustBe ""
    }
}
