package ghistabs.cpp.abi

import ghistabs.test.mustBe
import ghistabs.test.mustBeNull
import org.junit.jupiter.api.Test

class StructorOfTest {
    @Test
    fun `msvc tells its structors by their special names and spells them as the class does`() {
        Msvc.structorOf("??1Foo@ns@@QAE@XZ", "ns::Foo")?.displayName("ns::Foo") mustBe "~Foo"
        Msvc.structorOf("??0Foo@@QAE@XZ", "Foo") mustBe MsvcStructor.CONSTRUCTOR
        Msvc.structorOf("??_GFoo@@UAEPAXI@Z", "Foo")?.displayName("Foo") mustBe "`scalar_deleting_destructor'"
        Msvc.structorOf("?get@Foo@@QAEHXZ", "Foo").mustBeNull()
    }

    @Test
    fun `gcc 2 tells its structors by their prefix before the class`() {
        Gcc2Thunks.structorOf("_._9TiXmlNode", "TiXmlNode") mustBe Gcc2Structor.DESTRUCTOR
        Gcc2Thunks.structorOf("__9TiXmlNodeRC9TiXmlNode", "TiXmlNode")?.displayName("TiXmlNode") mustBe "TiXmlNode"
        Gcc2Thunks.structorOf("Clone__C9TiXmlNode", "TiXmlNode").mustBeNull()
    }

    @Test
    fun `without the class, gcc 2 tells only its destructor`() {
        Gcc2Thunks.structorOf("_._5Named") mustBe Gcc2Structor.DESTRUCTOR
        Gcc2Thunks.structorOf("__5Named").mustBeNull()
        CxxAbi.structorOf("_._5Named") mustBe Gcc2Structor.DESTRUCTOR
        CxxAbi.structorOf("??1Foo@@QAE@XZ") mustBe MsvcStructor.DESTRUCTOR
    }
}
