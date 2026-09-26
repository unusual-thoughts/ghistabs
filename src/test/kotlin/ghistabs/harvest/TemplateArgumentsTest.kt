package ghistabs.harvest

import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.parse.*
import ghistabs.parse.TypeDecl.Aggregate.Method
import ghistabs.test.mustBe
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * gcc ≥ 4.3 tags `Stack<Point,2>` as plain `Stack`; [TypeStore.toHarvest] restores the arguments from a
 * member's mangled name. Headless only because the demangler needs an initialized Ghidra Application.
 * The manglings are `hello_elf_gcc12`'s.
 */
@Tag("integration")
class TemplateArgumentsTest : AbstractGhidraHeadlessIntegrationTest() {
    private val cu = SourceFile.CUSource("hello.cc")

    private fun method(mangled: String) = Method<GlobalTypeId>(
        name = "m",
        mangled = mangled,
        signature = TypeDecl.Builtin(0),
        access = Access.PUBLIC,
        virt = VirtKind.NORMAL,
        isConst = false,
        isVolatile = false,
        vtableOffsetBits = null,
    )

    private fun struct(vararg methods: Method<GlobalTypeId>) = TypeDecl.Aggregate(
        kind = AggrKind.STRUCT,
        sizeBytes = 12L,
        bases = emptyList(),
        fields = emptyList(),
        methods = methods.toList(),
        vptrBasetype = null,
    )

    private fun harvestedName(name: String, body: GlobalTypeDecl): String? {
        val type = Type(cu = cu, id = GlobalTypeId(cu, 1), named = binding(name, body), body = body)
        return TypeStore(mutableMapOf(type.id to type)).toHarvest().first.getValue(type.id).name
    }

    @Test fun instantiationRegainsItsArguments() {
        harvestedName("Stack", struct(method("_ZN5StackI5PointLi2EE4pushERKS0_"))) mustBe "Stack<Point,2>"
    }

    @Test fun nestedClassRegainsItsEnclosersArguments() {
        harvestedName("Stack::Iter", struct(method("_ZN5StackIiLi4EE4IterC2Ev"))) mustBe "Stack<int,4>::Iter"
    }

    @Test fun abbreviatedLeafIsNotAdopted() {
        // `Ss` demangles to `std::string`, which is not `basic_string` with its arguments back.
        harvestedName("basic_string", struct(method("_ZNSs5clearEv"))) mustBe "basic_string"
    }

    @Test fun plainClassIsUntouched() {
        harvestedName("Shape", struct(method("_ZN5Shape4nameEv"))) mustBe "Shape"
    }

    @Test fun methodlessInstantiationStaysBare() {
        harvestedName("Stack", struct()) mustBe "Stack"
    }
}
