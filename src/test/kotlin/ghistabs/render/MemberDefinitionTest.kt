package ghistabs.render

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Pins the two rewrites that turn Ghidra's function model into legal C++: [asMemberDefinition] and
 * the array-extent placement in [declarator].
 */
class MemberDefinitionTest {
    @Test
    fun `a qualified constructor loses its return type and its explicit this`() {
        assertEquals(
            "XVImage::XVImage() { int x; }",
            "void XVImage::XVImage(XVImage *this) { int x; }".asMemberDefinition(),
        )
        assertEquals("XVImage::~XVImage()", "void XVImage::~XVImage(XVImage *this)".asMemberDefinition())
    }

    @Test
    fun `an ordinary member keeps its return type and loses only this`() {
        assertEquals(
            "int XVImage::ConvAddrFromFile(int addrIn)",
            "int XVImage::ConvAddrFromFile(XVImage *this,int addrIn)".asMemberDefinition(),
        )
    }

    @Test
    fun `a free function is left alone`() {
        // Dropping the parameter here would leave the body referring to a `this` that no longer
        // exists — there is no implicit one outside a member function.
        val free = "void error(string *this)"
        assertEquals(free, free.asMemberDefinition())
    }

    @Test
    fun `a class-body declaration is told its owner, having no qualifier to read one from`() {
        assertEquals("Image()", "void Image(Image * this)".asMemberDefinition("Image"))
        assertEquals("int size()", "int size(Image * this)".asMemberDefinition("Image"))
        // The owner is the *simple* name: vector<int>'s constructor is `vector`, not `vector<int>`.
        assertEquals("vector()", "void vector(vector<int> * this)".asMemberDefinition("vector"))
    }

    @Test
    fun `a nested parameter list does not end the signature early`() {
        assertEquals(
            // `run` is not Foo's constructor, so the return type stays; only `this` goes.
            "void Foo::run(void (*cb)(int,int),int n)",
            "void Foo::run(Foo *this,void (*cb)(int,int),int n)".asMemberDefinition(),
        )
    }

    @Test
    fun `an array extent follows the declarator, as C requires`() {
        assertEquals("char const _ZTS7XVImage[9]", declarator("char const[9]", "_ZTS7XVImage"))
        assertEquals("int grid[4][8]", declarator("int[4][8]", "grid"))
        // No extent to move: the type is emitted as-is, name appended.
        assertEquals("char * argv", declarator("char *", "argv"))
    }
}
