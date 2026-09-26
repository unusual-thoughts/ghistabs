package ghistabs.harvest

import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.parse.*
import ghistabs.parse.TypeDecl.Aggregate.Method
import ghistabs.test.GenericAddressResolver
import ghistabs.test.mustBe
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * gcc ≥ 4.3 tags `Stack<Point,2>` as plain `Stack`; [TypeStore.toHarvest] restores the arguments from a
 * member's mangled name, listed or bound by `this`. Headless only because the demangler needs an
 * initialized Ghidra Application. The manglings are `hello_elf_gcc12`'s and `xmltest`'s.
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

    private val id = GlobalTypeId(cu, 1)

    private fun harvestedName(
        name: String,
        body: GlobalTypeDecl,
        vararg others: Type,
        functions: List<Func> = emptyList(),
    ): String? {
        val types = listOf(Type(cu = cu, id = id, named = binding(name, body), body = body)) + others
        return TypeStore(types.associateByTo(mutableMapOf()) { it.id }).toHarvest(functions).first.getValue(id).name
    }

    /** An out-of-line member, its `this` declared as [self]. */
    private fun member(mangled: String, self: GlobalTypeDecl) = Func(
        name = mangled,
        addr = GenericAddressResolver.buildAddress(0x1000),
        decl = SymbolDecl.Function(mangled, FunctionScope.GLOBAL, TypeDecl.Builtin(-1)),
        cu = cu,
        params = listOf(
            Symbol(
                0,
                StabType.N_PSYM,
                SymbolDecl.Param("this", self, VariableLocation.STACK),
                0,
                sourceFileOf("hello.cc"),
            ),
        ),
    )

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

    // `this:p(0,178)=*(0,32)`: plain -gstabs lists no methods.
    @Test fun instantiationRegainsItsArgumentsFromThis() {
        val self = TypeDecl.InlineDef(GlobalTypeId(cu, 2), TypeDecl.Pointer(TypeDecl.Ref(id)))
        harvestedName(
            "MemPoolT",
            struct(),
            functions = listOf(member("_ZN8tinyxml28MemPoolTILm80EE5AllocEv", self)),
        ) mustBe "MemPoolT<80ul>"
    }

    // A later member's `this:p(0,161)` reuses the pointer the first one defined.
    @Test fun thisByIdBindsToo() {
        val pointer = Type(cu = cu, id = GlobalTypeId(cu, 2), named = null, body = TypeDecl.Pointer(TypeDecl.Ref(id)))
        harvestedName(
            "DynArray",
            struct(),
            pointer,
            functions = listOf(member("_ZN8tinyxml28DynArrayIcLm10EE4PushEc", TypeDecl.Ref(pointer.id))),
        ) mustBe "DynArray<char,10ul>"
    }
}
