package ghistabs.render

import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/**
 * Pins the array-extent placement in [declarator]. The other rewrite that turns Ghidra's function
 * model into legal C++ — dropping the explicit `this` and a constructor's return type — is
 * [Function.prototype], which assembles the prototype from the model instead of cutting it back out
 * of `prototypeString`, and so has no string surface to pin here; the fixture renders cover it.
 */
class DeclaratorTest {
    @Test
    fun `an array extent follows the declarator, as C requires`() {
        declarator("char const[9]", "_ZTS7MyKlass") mustBe "char const _ZTS7MyKlass[9]"
        declarator("int[4][8]", "grid") mustBe "int grid[4][8]"
        // No extent to move: the type is emitted as-is, name appended.
        declarator("char *", "argv") mustBe "char * argv"
    }
}
