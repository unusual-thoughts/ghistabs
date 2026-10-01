package ghistabs.hierarchy

import docking.widgets.tree.GTreeNode
import ghistabs.hierarchy.ClassHierarchy.Origin
import ghistabs.integration.FeatureFixtureTest
import ghistabs.parse.Access
import ghistabs.test.*
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource

/**
 * The Class Hierarchy window's model over `features/hello.cc`, on every compiler that built it:
 *
 * ```
 * class Shape { virtual double area() const = 0; … };
 * class Circle : public Shape { … };
 * struct Left : virtual Base { int l; };
 * struct Right : virtual Base { int r; };
 * struct Diamond : Left, Right, Named { int d; };
 * ```
 *
 * The bases are the stabs' own, virtuality included, gcc 2.x as much as Itanium.
 */
@Tag("integration")
class ClassHierarchyIntegrationTest : FeatureFixtureTest() {
    private fun ClassHierarchy.cls(name: String) = classes.singleOrNull { it.qualifiedName == name }
        ?: fail("no class $name in ${classes.map { it.qualifiedName }}")

    private fun ClassHierarchy.ClassInfo.baseSpelling() =
        bases.map { (if (it.isVirtual) "virtual " else "") + it.access?.name?.lowercase() + " " + it.name }

    @ParameterizedTest
    @MethodSource("hellos")
    fun `each class lists the bases its stab gives, virtual ones marked`(fixture: String) {
        load(fixture)
        val hierarchy = ClassHierarchy.of(program)

        val diamond = hierarchy.cls("Diamond")
        diamond.origin mustBe Origin.STABS
        diamond.baseSpelling() mustBe listOf("public Left", "public Right", "public Named")
        diamond.bases.all { it.target != null }.mustBeTrue("Diamond's bases resolve to classes: ${diamond.bases}")

        for (side in listOf("Left", "Right")) hierarchy.cls(side).baseSpelling() mustBe listOf("virtual public Base")
        hierarchy.cls("Circle").bases.map { it.target?.qualifiedName to it.access } mustBe
            listOf("Shape" to Access.PUBLIC)
        // `Base` has no member functions, so the stabs make it a plain struct, not a class: gcc ≥ 4.1
        // emits no typeinfo for it either, and the base is only a name.
        hierarchy.cls("Left").bases.single().target?.qualifiedName mustBeIn setOf(null, "Base")
    }

    /**
     * Read off the vftable's slots, so only where the pure slot's target is a function: with no
     * auto-analysis (as here), a dynamically linked `__cxa_pure_virtual` is a bare PLT entry.
     */
    @ParameterizedTest
    @MethodSource("hellos")
    fun `a class with a pure virtual slot is abstract`(fixture: String) {
        load(fixture)
        val hierarchy = ClassHierarchy.of(program)
        val pure = program.symbolTable.getSymbols("__cxa_pure_virtual").toList() +
            program.symbolTable.getSymbols("__pure_virtual").toList()
        if (pure.any { !it.isExternal && program.functionManager.getFunctionAt(it.address)?.isThunk == false }) {
            hierarchy.cls("Shape").isAbstract.mustBeTrue("Shape declares area() = 0")
        }
        hierarchy.cls("Circle").isAbstract.mustBeFalse()
    }

    @ParameterizedTest
    @MethodSource("hellos")
    fun `the tree files classes by namespace and expands each into its bases`(fixture: String) {
        load(fixture)
        val root = ClassHierarchyRootNode(program.name, ClassHierarchy.of(program))
        val diamond = root.children.single { it.name == "Diamond" }
        diamond.children.map(GTreeNode::getName) mustBe listOf("Left", "Right", "Named")
        diamond.children.first().children.map(GTreeNode::getName) mustBe listOf("virtual Base")
        diamond.children.first().children.single().isLeaf.mustBeTrue()
    }

    companion object {
        @JvmStatic
        fun hellos() = FEATURES.list().orEmpty().filter { it.startsWith("hello_") }.sorted()
    }
}
