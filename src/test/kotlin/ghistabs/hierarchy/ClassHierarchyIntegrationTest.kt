package ghistabs.hierarchy

import docking.widgets.tree.GTreeNode
import ghidra.program.model.symbol.SourceType
import ghistabs.hierarchy.ClassHierarchy.MemberKind
import ghistabs.hierarchy.ClassHierarchy.Origin
import ghistabs.importer.ClassHierarchyRecord
import ghistabs.importer.MemberAttrs
import ghistabs.integration.FeatureFixtureTest
import ghistabs.parse.Access
import ghistabs.parse.VirtKind
import ghistabs.runTransaction
import ghistabs.test.*
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Assumptions.assumeTrue
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
        diamond.bases.all { hierarchy[it] != null }.mustBeTrue("Diamond's bases resolve to classes: ${diamond.bases}")

        for (side in listOf("Left", "Right")) hierarchy.cls(side).baseSpelling() mustBe listOf("virtual public Base")
        hierarchy.cls("Circle").bases.map { hierarchy[it]?.qualifiedName to it.access } mustBe
            listOf("Shape" to Access.PUBLIC)
        // `Base` has no member functions, so the stabs make it a plain struct, not a class: gcc ≥ 4.1
        // emits no typeinfo for it either, and the base is only a name.
        hierarchy[hierarchy.cls("Left").bases.single()]?.qualifiedName mustBeIn setOf(null, "Base")
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
        // A static data member is a label, with the stabs' attributes, mangled or not.
        val count = hierarchy.cls("Shape").members.single { it.name == "count" }
        count.kind mustBe MemberKind.LABEL
        count.attrs mustBe MemberAttrs(Access.PUBLIC, VirtKind.STATIC)
        circle.single { it.name == "name" }.attrs mustBe MemberAttrs(Access.PUBLIC, VirtKind.VIRTUAL, isConst = true)
        // Only an overloaded function spells its parameters.
        circle.single { it.name == "name" }.label mustBe "name"
        for (m in hierarchy.classes.flatMap { it.members }.filter { it.isOverloaded }) {
            m.label.startsWith(m.name + "(").mustBeTrue("${m.label} spells its parameters")
            ("this" in m.label).mustBeFalse()
        }
        // gcc 2.x: a destructor's `int __in_chrg` is no more the source's than `this`, and 2.95's
        // `__thunk_16__._7Diamond` is a thunk.
        val diamond = hierarchy.cls("Diamond").members.filter { it.name == "~Diamond" }
        diamond.all { it.label.substringBefore(" [") in setOf("~Diamond", "~Diamond()") }
            .mustBeTrue("${diamond.map { it.label }}")
        // gcc >= 3 emits it once per variant, which its linkage name says; gcc 2.x once, with `__in_chrg`.
        val variants = diamond.flatMap { it.variants }
        if (fixture in setOf("hello_elf_gcc272", "hello_elf_gcc295")) {
            variants mustBe emptyList()
        } else {
            variants.isNotEmpty().mustBeTrue("${diamond.map { it.label }}")
            variants.all { it.code.startsWith("D") }.mustBeTrue("$variants")
        }
        if (fixture == "hello_elf_gcc295") diamond.count { it.kind == MemberKind.THUNK } mustBe 1

        val node = ClassHierarchyRootNode(program.name, hierarchy).children.single { it.name == "Circle" }
        node.children.first().name mustBe "Shape"
        node.children.filterIsInstance<MemberNode>().map { it.member } mustBe circle
        // Under a base, a class shows only its own bases.
        node.children.first().children.none { it is MemberNode }.mustBeTrue()
        ClassHierarchyRootNode(program.name, hierarchy, showMembers = false).children.single { it.name == "Circle" }
            .children.none { it is MemberNode }.mustBeTrue()
    }

    /** `Point` is a plain struct whose implicit members g++ never emitted: hidden until asked for. */
    @ParameterizedTest
    @MethodSource("hellos")
    fun `an empty class is hidden unless shown`(fixture: String) {
        load(fixture)
        val hierarchy = ClassHierarchy.of(program)
        val point = hierarchy.classes.singleOrNull { it.path == listOf("Point") }
        assumeTrue(point != null, "$fixture builds no class for Point")
        hierarchy.isEmpty(point!!).mustBeTrue("Point should be empty: $point")
        hierarchy.isEmpty(hierarchy.classes.single { it.path == listOf("Diamond") }) mustBe false

        ClassHierarchyRootNode(program.name, hierarchy).children.none { it.name == "Point" }.mustBeTrue()
        ClassHierarchyRootNode(program.name, hierarchy, showEmpty = true).children.any { it.name == "Point" }
            .mustBeTrue()
    }

    @ParameterizedTest
    @MethodSource("hellos")
    fun `member attributes are recorded with the class pass off`(fixture: String) {
        load(fixture) { buildClasses = false }
        val attrsAt = ClassHierarchyRecord.memberAttrs(program)
        // Circle::name, by whichever symbol spells it: `_ZNK6Circle4nameEv`, `name__C6Circle`, demangled.
        val name = program.symbolTable.getAllSymbols(true).iterator().asSequence()
            .filter { it.getName(true).let { n -> "Circle" in n && "name" in n } }
            .firstNotNullOfOrNull { attrsAt(it.address) }
        name mustBe MemberAttrs(Access.PUBLIC, VirtKind.VIRTUAL, isConst = true)
    }

    @ParameterizedTest
    @MethodSource("hellos")
    fun `inverted, a basal class expands into the classes derived from it, each under every base`(fixture: String) {
        load(fixture)
        val root =
            ClassHierarchyRootNode(program.name, ClassHierarchy.of(program), showMembers = false, inverted = true)
        root.children.none {
            it.name == "Circle" || it.name == "Diamond"
        }.mustBeTrue("${root.children.map { it.name }}")
        root.children.single { it.name == "Shape" }.children.map { it.name } mustBe listOf("Circle")
        // Diamond derives from Left, Right and Named: it shows under each.
        root.children.single { it.name == "Named" }.children.map { it.name } mustBe listOf("Diamond")
        val base = root.children.singleOrNull { it.name == "Base" }
        val left = (base?.children?.single { it.name.startsWith("Left") } ?: root.children.single { it.name == "Left" })
        if (base != null) {
            left.name mustBe "Left (virtual)"
            "derives virtually" mustBeIn left.toolTip
        }
        left.children.map { it.name } mustBe listOf("Diamond")
    }

    @ParameterizedTest
    @MethodSource("hellos")
    fun `the hierarchy serializes and reads back equal`(fixture: String) {
        load(fixture)
        val hierarchy = ClassHierarchy.of(program)
        val json = Json.encodeToString(hierarchy)
        Json.decodeFromString<ClassHierarchy>(json) mustBe hierarchy
        "\"Diamond\"" mustBeIn json
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

    /** What Navigate on Incoming selects for a location: the member there, under the class that lists it. */
    @ParameterizedTest
    @MethodSource("hellos")
    fun `an address finds its member's node, inverted too`(fixture: String) {
        load(fixture)
        val hierarchy = ClassHierarchy.of(program)
        for (inverted in listOf(false, true)) {
            val root = ClassHierarchyRootNode(program.name, hierarchy, inverted = inverted)
            for (name in listOf("Circle", "Diamond")) {
                val cls = hierarchy.cls(name)
                val member = cls.members.first { it.kind == MemberKind.FUNCTION }
                val node =
                    root.nodeAt(listOf(member.address)) as? MemberNode ?: fail("$name: no node at ${member.address}")
                node.member mustBe member
                (node.parent as ClassNode).info?.id mustBe cls.id
            }
            root.nodeAt(listOf("ffffffff")) mustBe null
        }
    }

    companion object {
        @JvmStatic
        fun hellos() = FEATURES.list().orEmpty().filter { it.startsWith("hello_") }.sorted()
    }
}
