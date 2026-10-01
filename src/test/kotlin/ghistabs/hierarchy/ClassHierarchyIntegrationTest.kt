package ghistabs.hierarchy

import docking.widgets.tree.GTreeNode
import ghidra.program.model.symbol.SourceType
import ghistabs.hierarchy.ClassHierarchy.MemberKind
import ghistabs.hierarchy.ClassHierarchy.Origin
import ghistabs.integration.FeatureFixtureTest
import ghistabs.parse.Access
import ghistabs.runTransaction
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
        diamond.children.filterIsInstance<ClassNode>().map(GTreeNode::getName) mustBe listOf("Left", "Right", "Named")
        diamond.children.first().children.map(GTreeNode::getName) mustBe listOf("virtual Base")
        diamond.children.first().children.single().isLeaf.mustBeTrue()
        "virtual base class" mustBeIn diamond.children.first().children.single().toolTip
    }

    @ParameterizedTest
    @MethodSource("hellos")
    fun `a class lists its functions and labels, its vtable first`(fixture: String) {
        load(fixture)
        val hierarchy = ClassHierarchy.of(program)
        val circle = hierarchy.cls("Circle").members
        circle.first().kind mustBe MemberKind.VTABLE
        circle.single { it.name == "name" }.kind mustBe MemberKind.FUNCTION
        // A static data member is a plain label, mangled or not.
        hierarchy.cls("Shape").members.single { it.name == "count" }.kind mustBe MemberKind.LABEL
        // Only an overloaded function spells its parameters.
        circle.single { it.name == "name" }.label mustBe "name"
        for (m in hierarchy.classes.flatMap { it.members }.filter { it.isOverloaded }) {
            m.label.startsWith(m.name + "(").mustBeTrue("${m.label} spells its parameters")
            ("this" in m.label).mustBeFalse()
        }

        val node = ClassHierarchyRootNode(program.name, hierarchy).children.single { it.name == "Circle" }
        node.children.first().name mustBe "Shape"
        node.children.filterIsInstance<MemberNode>().map { it.member } mustBe circle
        // Under a base, a class shows only its own bases.
        node.children.first().children.none { it is MemberNode }.mustBeTrue()
        ClassHierarchyRootNode(program.name, hierarchy, showMembers = false).children.single { it.name == "Circle" }
            .children.none { it is MemberNode }.mustBeTrue()
    }

    /** What [replaceRoot] carries over: a path by names, found again in the rebuilt tree. */
    @ParameterizedTest
    @MethodSource("hellos")
    fun `a path in the tree is found again after a rebuild for a renamed member`(fixture: String) {
        load(fixture)
        val before = ClassHierarchyRootNode(program.name, ClassHierarchy.of(program))
        val left = before.children.single { it.name == "Diamond" }.children.first()
        val circle = before.children.single { it.name == "Circle" }
        val leftSteps = steps(left)
        val circleSteps = steps(circle)
        leftSteps mustBe listOf("Diamond" to 0, "Left" to 0)

        val name = program.functionManager.getFunctions(true)
            .first { it.name == "name" && it.parentNamespace.name == "Circle" }
        program.runTransaction { name.setName("label", SourceType.USER_DEFINED) }
        val after = ClassHierarchyRootNode(program.name, ClassHierarchy.of(program))

        steps(after.find(leftSteps) ?: fail("Diamond/Left is gone")) mustBe leftSteps
        val rebuilt = after.find(circleSteps) ?: fail("Circle is gone")
        rebuilt.children.map { it.name }.let { names ->
            ("label" in names).mustBeTrue("$names")
            ("name" in names).mustBeFalse()
        }
    }

    companion object {
        @JvmStatic
        fun hellos() = FEATURES.list().orEmpty().filter { it.startsWith("hello_") }.sorted()
    }
}
