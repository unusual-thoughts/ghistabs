package ghistabs.parse

import ghistabs.render.cxxKeyword
import ghistabs.test.mustBe
import ghistabs.test.mustBeFalse
import ghistabs.test.mustBeTrue
import org.junit.jupiter.api.Test

/**
 * The two class-ness questions asked of a `s` body, which differ at exactly one term and used to be
 * answered by two hand-rolled predicates that disagreed: [TypeDecl.Struct.hasCxxSurface] (is this C++
 * at all — drives class materialization) and [TypeDecl.Struct.isCxxClass] (was the keyword `class` —
 * drives the rendered keyword and its default access).
 */
class StructKindTest {
    private fun struct(stab: String) =
        Parser(stab).parseSymbol().mustBeOk().let { (it as SymbolDecl.NamedType).type as TypeDecl.Struct }

    @Test
    fun `a public base is C++ but not evidence of the class keyword`() {
        // `struct D : public B {}` — idiomatic C++, and gcc emits `!N,` only for C++ records.
        val d = struct("D:T(0,6)=s4!1,020,(0,5);;;")
        d.hasCxxSurface.mustBeTrue()
        d.isCxxClass.mustBeFalse()
        d.cxxKeyword mustBe "struct"
    }

    @Test
    fun `a non-public base is evidence of the class keyword`() {
        // Default base access is private for `class`, public for `struct`.
        val d = struct("D:T(0,6)=s4!1,000,(0,5);;;")
        d.hasCxxSurface.mustBeTrue()
        d.isCxxClass.mustBeTrue()
        d.cxxKeyword mustBe "class"
    }

    @Test
    fun `a plain C struct is neither`() {
        val foo = struct("Foo:T(0,5)=s8x:(0,1),0,32;y:(0,1),32,32;;;")
        foo.hasCxxSurface.mustBeFalse()
        foo.isCxxClass.mustBeFalse()
        foo.cxxKeyword mustBe "struct"
    }

    @Test
    fun `a union keeps its keyword however C++ it looks`() {
        // gcc 2.95 emits implicit ctors/operator= on C unions compiled as C++ (pthread_mutex_t).
        // Those make it a C++ record, but `union` is read from the descriptor, never guessed.
        val u = struct("U:T(0,7)=u4a:(0,1),0,32;__as::(0,8)=#(0,7),(0,1),(0,20);:__as__1U;2A.;;")
        u.hasCxxSurface.mustBeTrue()
        u.isCxxClass.mustBeTrue()
        u.cxxKeyword mustBe "union"
    }
}
