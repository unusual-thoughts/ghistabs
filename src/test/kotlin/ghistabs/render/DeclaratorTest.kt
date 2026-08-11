package ghistabs.render

import org.junit.jupiter.api.Assertions.assertEquals
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
        assertEquals("char const _ZTS7XVImage[9]", declarator("char const[9]", "_ZTS7XVImage"))
        assertEquals("int grid[4][8]", declarator("int[4][8]", "grid"))
        // No extent to move: the type is emitted as-is, name appended.
        assertEquals("char * argv", declarator("char *", "argv"))
    }
}
