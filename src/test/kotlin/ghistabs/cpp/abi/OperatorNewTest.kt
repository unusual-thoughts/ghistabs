package ghistabs.cpp.abi

import ghistabs.cpp.abi.gcc2.Gcc2Plain
import ghistabs.cpp.abi.gcc2.Gcc2Thunks
import ghistabs.cpp.abi.itanium.Itanium
import ghistabs.cpp.abi.msvc.Msvc
import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

class OperatorNewTest {
    @Test
    fun `each abi knows operator new by its own mangling and by its demangled name`() {
        ("??2@YAPAXI@Z" in Msvc.operatorNewNames) mustBe true
        ("_Znwj" in Msvc.operatorNewNames) mustBe false
        ("_Znwm" in Itanium.operatorNewNames) mustBe true
        ("__builtin_new" in Gcc2Thunks.operatorNewNames) mustBe true
        listOf(Msvc, Itanium, Gcc2Plain).all { "operator new" in it.operatorNewNames } mustBe true
    }
}
