package ghicpp.gui

import docking.widgets.tree.GTreeNode
import docking.widgets.tree.support.GTreeFilter
import ghicpp.Access
import ghicpp.ClassNaming
import ghicpp.MemberAttrs
import ghicpp.MemberAttrs.Companion.memberAttrs
import ghicpp.VirtKind
import ghicpp.hierarchy.*
import ghicpp.hierarchy.ClassHierarchy.MemberKind
import ghicpp.hierarchy.ClassHierarchy.Origin
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.VariableUtilities
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghistabs.integration.FeatureFixtureTest
import ghistabs.path
import ghistabs.runTransaction
import ghistabs.test.mustBe
import ghistabs.test.mustBeFalse
import ghistabs.test.mustBeIn
import ghistabs.test.mustBeNull
import ghistabs.test.mustBeTrue
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.awt.dnd.DnDConstants

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

    private fun ClassHierarchy.ClassView.baseSpelling() =
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
        // Laid one after another from the start; a virtual base has no fixed place.
        val offsets = diamond.bases.map { it.offset }
        offsets.first() mustBe 0L
        offsets.zipWithNext().all { (a, b) -> a != null && b != null && a < b }.mustBeTrue("increasing: $offsets")
        hierarchy.cls("Left").bases.single().offset mustBe null

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
        val root = ClassTreeRoot(program.name, ClassHierarchy.of(program))
        val diamond = root.children.single { it.name == "Diamond" }
        diamond.children.filterIsInstance<ClassNode>().map(GTreeNode::getName) mustBe listOf("Left", "Right", "Named")
        diamond.children.first().children.map(GTreeNode::getName) mustBe listOf("virtual Base")
        val right = diamond.children.filterIsInstance<ClassNode>()[1]
        ("at offset 0x" in right.toolTip).mustBeTrue(right.toolTip)
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
        count.attrs mustBe MemberAttrs(Access.PUBLIC, VirtKind.STATIC, source = SourceType.IMPORTED)
        circle.single { it.name == "name" }.attrs mustBe
            MemberAttrs(Access.PUBLIC, VirtKind.VIRTUAL, isConst = true, source = SourceType.IMPORTED)
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

        val node = ClassTreeRoot(program.name, hierarchy).children.single { it.name == "Circle" }
        node.children.first().name mustBe "Shape"
        node.children.filterIsInstance<MemberNode>().map { it.member } mustBe circle
        // Under a base, a class shows only its own bases.
        node.children.first().children.none { it is MemberNode }.mustBeTrue()
        ClassTreeRoot(program.name, hierarchy, memberKinds = emptySet()).children.single { it.name == "Circle" }
            .children.none { it is MemberNode }.mustBeTrue()
        // Only the kinds shown: here its vtable and typeinfo, not its functions.
        ClassTreeRoot(program.name, hierarchy, memberKinds = setOf(MemberKind.VTABLE, MemberKind.ABI))
            .children.single { it.name == "Circle" }.children.filterIsInstance<MemberNode>()
            .map { it.member } mustBe circle.filter { it.kind == MemberKind.VTABLE || it.kind == MemberKind.ABI }
    }

    @ParameterizedTest
    @MethodSource("hellos")
    fun `a virtual function goes to the base function it overrides`(fixture: String) {
        load(fixture)
        val hierarchy = ClassHierarchy.of(program)
        val circle = hierarchy.cls("Circle")
        val shape = hierarchy.cls("Shape")
        fun ClassHierarchy.ClassView.function(name: String) =
            members.single { it.name == name && it.kind == MemberKind.FUNCTION }

        hierarchy.overridden(circle, circle.function("name")) mustBe shape.function("name")
        // Shape's own is the first declaration, and a pure virtual has no function to go to.
        hierarchy.overridden(shape, shape.function("name")) mustBe null
        hierarchy.overridden(circle, circle.function("area")) mustBe null
        // A destructor overrides its base's: the same variant when the base emitted it, else another.
        val named = hierarchy.cls("Named")
        val diamond = hierarchy.cls("Diamond")
        for (dtor in diamond.members.filter { it.name == "~Diamond" && it.kind == MemberKind.FUNCTION }) {
            val base = hierarchy.overridden(diamond, dtor)
            base?.name mustBe "~Named"
            (base in named.members).mustBeTrue("${base?.label} is Named's")
            val sameVariant = named.members.filter { it.name == "~Named" }
                .firstOrNull { it.variants.any(dtor.variants::contains) }
            if (sameVariant != null) base mustBe sameVariant
        }
    }

    @ParameterizedTest
    @MethodSource("hellos")
    fun `renaming a class renames its structors, structs and what derived classes name after it`(fixture: String) {
        load(fixture)
        val before = ClassHierarchy.of(program)
        val dtm = program.dataTypeManager
        val shape = before.cls("Shape")
        val selfBases = dtm.allDataTypes.asSequence().count {
            it.name == "Shape" && "!internal" in it.categoryPath.path
        }
        val vftables = dtm.allDataTypes.asSequence().filter { it.name.startsWith("Shape_vftable") }.count()
        val runs = dtm.allDataTypes.asSequence().count { it.name.startsWith("Shape_fields_") }
        val left = before.cls("Left")
        val diamondStruct = { program.dataTypeManager.getDataType(before.cls("Diamond").structId!!) as Structure }
        val leftField = diamondStruct().definedComponents.any { it.fieldName == "_base_Left" }

        program.runTransaction("rename") {
            program.renameClass(before, shape, "Figure") mustBe emptyList()
            program.renameClass(before, left, "Port") mustBe emptyList()
        }

        val after = ClassHierarchy.of(program)
        val figure = after.cls("Figure")
        figure.id mustBe shape.id
        figure.origin mustBe Origin.STABS
        figure.members.filter { it.kind == MemberKind.FUNCTION }.map { it.name }.toSet()
            .containsAll(setOf("Figure", "~Figure")).mustBeTrue("${figure.members.map { it.name }}")
        figure.members.none { it.name == "Shape" || it.name == "~Shape" }.mustBeTrue()
        dtm.getDataType(figure.structId!!).name mustBe "Figure"
        dtm.allDataTypes.asSequence().count { it.name.startsWith("Figure_vftable") } mustBe vftables
        dtm.allDataTypes.asSequence().none { it.name.startsWith("Shape_vftable") }.mustBeTrue()
        dtm.allDataTypes.asSequence().none { it.name.startsWith("Shape_fields_") }.mustBeTrue()
        dtm.allDataTypes.asSequence().count { it.name.startsWith("Figure_fields_") } mustBe runs
        dtm.allDataTypes.asSequence().none { it.name == "Shape" && "!internal" in it.categoryPath.path }.mustBeTrue()
        dtm.allDataTypes.asSequence().count { it.name == "Figure" && "!internal" in it.categoryPath.path } mustBe
            selfBases
        after.cls("Circle").baseSpelling() mustBe listOf("public Figure")
        // Diamond's base field and vftable label for Left follow it.
        val fields = diamondStruct().definedComponents.map { it.fieldName }
        ("_base_Left" in fields).mustBeFalse()
        ("_base_Port" in fields) mustBe leftField
        after.cls("Diamond").members.none { it.name == "vftable_for_Left" }.mustBeTrue()
    }

    @ParameterizedTest
    @MethodSource("hellos")
    fun `a dropped class becomes the child of the class it is dropped on, never its own base`(fixture: String) {
        load(fixture)
        val h = ClassHierarchy.of(program)
        val (shape, circle, named) = listOf("Shape", "Circle", "Named").map { h.cls(it) }
        val (left, diamond) = listOf("Left", "Diamond").map { h.cls(it) }
        val shapeClause = circle.bases.single()
        fun refusal(plan: () -> Drop) = plan().error

        // Bases below: Circle dropped on Shape would make Shape derive from what derives from it.
        refusal { h.planDrop(owner = shape, base = circle, removedFrom = null, edge = null) } mustBe
            "Circle derives from Shape: drop it on the root or a common base first"
        refusal { h.planDrop(owner = circle, base = shape, removedFrom = null, edge = null) } mustBe
            "Circle already derives from Shape"
        // Left moved from under Diamond to under Circle: Diamond loses it, Circle gains it.
        val leftClause = diamond.bases.first { it.targetId == left.id }
        h.planDrop(owner = circle, base = left, removedFrom = diamond, edge = leftClause).edits mustBe listOf(
            BaseEdit(diamond, leftClause, null),
            BaseEdit(circle, null, left),
        )

        // Derived below: Circle moved from under Shape to under Named swaps its base in place; copied, adds one.
        h.planDrop(owner = circle, base = named, removedFrom = circle, edge = shapeClause).edits mustBe
            listOf(BaseEdit(circle, shapeClause, named))
        h.planDrop(owner = circle, base = named, removedFrom = null, edge = shapeClause).edits mustBe
            listOf(BaseEdit(circle, null, named))
        // On the root, it only leaves.
        h.planDrop(owner = circle, base = null, removedFrom = circle, edge = shapeClause).edits mustBe
            listOf(BaseEdit(circle, shapeClause, null))
        refusal { h.planDrop(owner = shape, base = null, removedFrom = null, edge = null) } mustBe
            "Shape has no base here to remove"
    }

    @ParameterizedTest
    @MethodSource("hellos")
    fun `editing a base's attributes respells its clause in place`(fixture: String) {
        load(fixture)
        val h = ClassHierarchy.of(program)
        val (shape, circle, named) = listOf("Shape", "Circle", "Named").map { h.cls(it) }
        val shapeClause = circle.bases.single()
        val edit = h.reclause(circle, shapeClause)!!
        edit mustBe BaseEdit(circle, shapeClause, shape)
        edit.isReclause.mustBeTrue()
        val clause = shapeClause.copy(isVirtual = true, access = Access.PROTECTED)
        edit.bases(clause) mustBe listOf(clause)
        // A clause the class doesn't hold, or one naming no class of the program's, has nothing to edit.
        h.reclause(named, shapeClause).mustBeNull()
        h.reclause(circle, shapeClause.copy(targetId = null)).mustBeNull()
    }

    @ParameterizedTest
    @MethodSource("hellos")
    fun `bases set by hand stand over the stabs', placed in the struct at their offset`(fixture: String) {
        load(fixture)
        val h = ClassHierarchy.of(program)
        val (circle, named) = listOf("Circle", "Named").map { h.cls(it) }
        val edit = h.planDrop(owner = circle, base = named, removedFrom = null, edge = null).edits.single()
        val clause = ClassHierarchy.BaseRef("Named", named.id, false, Access.PROTECTED, null)
        val struct = { program.dataTypeManager.getDataType(circle.structId!!) as Structure }
        val end = struct().length

        program.overwrittenBy(circle, named, 0).isNotEmpty().mustBeTrue("Circle's own fields start at 0")
        program.overwrittenBy(circle, named, end) mustBe emptyList()
        program.runTransaction("edit") {
            program.setBases(circle, edit.bases(clause))
            program.placeBase(circle, named, end, isVirtual = false, baseCount = 2) mustBe null
        }

        val after = ClassHierarchy.of(program).cls("Circle")
        after.origin mustBe Origin.EDITED
        after.baseSpelling() mustBe listOf("public Shape", "protected Named")
        val field = struct().getComponentContaining(end)
        field.offset mustBe end
        field.fieldName mustBe "_base_Named"
        field.dataType.isEquivalent(program.embeddingOf(named)).mustBeTrue("${field.dataType}")
        // The lone base field it had takes its base's name, now there are two.
        struct().definedComponents.none { it.fieldName == "_base_" }.mustBeTrue()
    }

    @ParameterizedTest
    @MethodSource("hellos")
    fun `a member dropped on a class moves into its namespace`(fixture: String) {
        load(fixture)
        val h = ClassHierarchy.of(program)
        val (circle, named) = listOf("Circle", "Named").map { h.cls(it) }
        val area = circle.members.single { it.name == "area" && it.kind == MemberKind.FUNCTION }

        program.memberSource(area) mustBe "the stabs"
        area.isMovable.mustBeTrue()
        // A vtable's or typeinfo's label names its class, so it doesn't drag.
        circle.members.filter { it.kind == MemberKind.VTABLE || it.kind == MemberKind.ABI }.none { it.isMovable }
            .mustBeTrue()
        program.runTransaction("move") { program.moveMember(area, named) }

        val after = ClassHierarchy.of(program)
        after.cls("Named").members.any { it.name == "area" && it.address == area.address }.mustBeTrue()
        after.cls("Circle").members.none { it.name == "area" }.mustBeTrue()
    }

    @ParameterizedTest
    @MethodSource("hellos")
    fun `a class moved into a namespace takes its vftables, categories and struct along`(fixture: String) {
        load(fixture)
        val h = ClassHierarchy.of(program)
        val circle = h.cls("Circle")
        val dtm = program.dataTypeManager
        fun tablesAt(path: List<String>) =
            dtm.getCategory(ClassNaming.vftableCategory(path))?.dataTypes.orEmpty().map { it.name }.toSet()
        val vftables = tablesAt(listOf("Circle"))
        val shapeTables = dtm.getCategory(ClassNaming.vftableCategory(listOf("Shape")))?.dataTypes.orEmpty().size
        val ns = { program.symbolTable.getSymbol(circle.id).`object` as GhidraClass }
        fun foundStruct() = VariableUtilities.findExistingClassStruct(ns(), dtm)?.let(dtm::getID)

        checkNamespaceMove(listOf("Circle"), emptyList()) mustBe "Circle is already there"
        checkNamespaceMove(listOf("geo"), listOf("geo", "inner")) mustBe "a namespace can't move into itself"
        checkNamespaceMove(listOf("Circle"), listOf("geo")) mustBe null

        val geo = program.runTransaction("namespace") {
            program.symbolTable.createNameSpace(null, "geo", SourceType.USER_DEFINED)
        }
        program.runTransaction("move") { program.relocateNamespace(ns(), geo) } mustBe emptyList()
        fun check(path: List<String>) {
            val moved = ClassHierarchy.of(program)[circle.id]!!
            moved.path mustBe path
            moved.structId mustBe circle.structId
            foundStruct() mustBe circle.structId
            tablesAt(path) mustBe vftables
            if (vftables.isNotEmpty()) tablesAt(listOf("Circle")) mustBe emptySet()
            dtm.getCategory(ClassNaming.vftableCategory(listOf("Shape")))?.dataTypes.orEmpty().size mustBe shapeTables
        }
        check(listOf("geo", "Circle"))

        // In the tree, a class filed under its namespace and the namespace itself drop on the root.
        val moved = ClassHierarchy.of(program)
        val root = ClassTreeRoot(program.name, moved)
        val geoNode = root.children.single { it is NamespaceNode && it.name == "geo" }
        val circleNode = geoNode.children.single { it is ClassNode && it.name == "Circle" }
        moved.dropRefusal(circleNode, root, DnDConstants.ACTION_MOVE) mustBe null
        moved.dropRefusal(geoNode, root, DnDConstants.ACTION_MOVE) mustBe "geo is already there"
        moved.dropRefusal(circleNode, geoNode, DnDConstants.ACTION_MOVE) mustBe "geo::Circle is already there"
        // Onto another class, it becomes its base; a namespace can't go there.
        val namedNode = root.children.single { it is ClassNode && it.name == "Named" }
        moved.dropRefusal(circleNode, namedNode, DnDConstants.ACTION_MOVE) mustBe null
        moved.dropRefusal(geoNode, namedNode, DnDConstants.ACTION_MOVE) mustBe
            "a namespace only drops on another namespace or the root"

        program.runTransaction("rename") { program.relocateNamespace(geo, geo.parentNamespace, "shapes") } mustBe
            emptyList()
        check(listOf("shapes", "Circle"))

        program.runTransaction("back") { program.relocateNamespace(ns(), program.globalNamespace) } mustBe emptyList()
        ClassHierarchy.of(program)[circle.id]!!.path mustBe listOf("Circle")
        foundStruct() mustBe circle.structId
    }

    /** A function's mangled label, or a static member's second one, isn't a member of its own. */
    @ParameterizedTest
    @MethodSource("hellos")
    fun `a label spelling again a member it sits on is left out, and shown in its tooltip`(fixture: String) {
        load(fixture)
        val before = ClassHierarchy.of(program)
        val area = before.cls("Circle").members.single { it.name == "area" && it.kind == MemberKind.FUNCTION }
        val count = before.cls("Shape").members.singleOrNull { it.name == "count" && it.kind == MemberKind.LABEL }
        assumeTrue(count != null, "$fixture lists no Shape::count")
        val st = program.symbolTable
        fun ns(cls: String) = st.getSymbol(before.cls(cls).id).`object` as GhidraClass
        fun at(m: ClassHierarchy.Member) = program.addressFactory.getAddress(m.address)
        program.runTransaction("labels") {
            st.createLabel(at(area), "_ZNK6Circle4areaEv", ns("Circle"), SourceType.IMPORTED)
            st.createLabel(at(count!!), "_ZN5Shape5countE", ns("Shape"), SourceType.IMPORTED)
        }

        val after = ClassHierarchy.of(program)
        val circle = after.cls("Circle").members
        circle.none { it.name == "_ZNK6Circle4areaEv" }.mustBeTrue("${circle.map { it.label }}")
        val shown = circle.single { it.name == "area" && it.kind == MemberKind.FUNCTION }
        ("_ZNK6Circle4areaEv" in shown.aliases).mustBeTrue("${shown.aliases}")
        ("_ZNK6Circle4areaEv" in MemberNode(shown).toolTip).mustBeTrue()
        val shape = after.cls("Shape").members.filter { it.kind == MemberKind.LABEL && it.address == count!!.address }
        shape.map { it.name } mustBe listOf("count")
        ("_ZN5Shape5countE" in shape.single().aliases).mustBeTrue("${shape.single().aliases}")
    }

    /** `Builtins` is a plain struct whose implicit members g++ never emitted: hidden until asked for. */
    @ParameterizedTest
    @MethodSource("hellos")
    fun `an empty class is hidden unless shown`(fixture: String) {
        load(fixture)
        val hierarchy = ClassHierarchy.of(program)
        val plain = hierarchy.classes.singleOrNull { it.path == listOf("Builtins") }
        assumeTrue(plain != null, "$fixture builds no class for Builtins")
        hierarchy.isEmpty(plain!!).mustBeTrue("Builtins should be empty: $plain")
        hierarchy.isEmpty(hierarchy.classes.single { it.path == listOf("Diamond") }) mustBe false

        ClassTreeRoot(program.name, hierarchy).children.none { it.name == "Builtins" }.mustBeTrue()
        ClassTreeRoot(program.name, hierarchy, showEmpty = true).children.any { it.name == "Builtins" }
            .mustBeTrue()
    }

    @ParameterizedTest
    @MethodSource("hellos")
    fun `member attributes are recorded with the class pass off`(fixture: String) {
        load(fixture) { buildClasses = false }
        // Circle::name, by whichever symbol spells it: `_ZNK6Circle4nameEv`, `name__C6Circle`, demangled.
        val name = program.symbolTable.getAllSymbols(true).iterator().asSequence()
            .filter { it.getName(true).let { n -> "Circle" in n && "name" in n } }
            .firstNotNullOfOrNull { program.memberAttrs(it.address) }
        name mustBe MemberAttrs(Access.PUBLIC, VirtKind.VIRTUAL, isConst = true, source = SourceType.IMPORTED)
    }

    @ParameterizedTest
    @MethodSource("hellos")
    fun `inverted, a basal class expands into the classes derived from it, each under every base`(fixture: String) {
        load(fixture)
        val root =
            ClassTreeRoot(program.name, ClassHierarchy.of(program), memberKinds = emptySet(), inverted = true)
        root.children.none {
            it.name == "Circle" || it.name == "Diamond"
        }.mustBeTrue("${root.children.map { it.name }}")
        root.children.single { it.name == "Shape" }.children.map { it.name } mustBe listOf("Circle", "Rect")
        // Diamond derives from Left, Right and Named, Label from Rect and Named: each shows under each.
        root.children.single { it.name == "Named" }.children.map { it.name } mustBe listOf("Diamond", "Label")
        val base = root.children.singleOrNull { it.name == "Base" }
        val left = (base?.children?.single { it.name.startsWith("Left") } ?: root.children.single { it.name == "Left" })
        if (base != null) {
            left.name mustBe "Left (virtual)"
            "derives virtually" mustBeIn left.toolTip
        }
        left.children.map { it.name } mustBe listOf("Diamond")
    }

    /** What the window's action context hands the symbol actions: a member's symbol, a class's namespace's. */
    @ParameterizedTest
    @MethodSource("hellos")
    fun `each member and class finds its symbol again`(fixture: String) {
        load(fixture)
        val hierarchy = ClassHierarchy.of(program)
        val symtab = program.symbolTable
        for (cls in hierarchy.classes) {
            symtab.getSymbol(cls.id)?.name mustBe cls.name
            for (m in cls.members) {
                val sym = symtab.getSymbol(m.symbolId ?: fail("no symbol id for ${cls.qualifiedName}::${m.name}"))
                    ?: fail("no symbol for ${cls.qualifiedName}::${m.name}")
                (sym.name to sym.address.toString()) mustBe (m.name to m.address)
                // An import, from the class's namespace under its library.
                if (m.library == null) sym.parentNamespace.id mustBe cls.id
                if (m.library != null) sym.parentNamespace.path mustBe cls.path
            }
        }
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
        val before = ClassTreeRoot(program.name, ClassHierarchy.of(program))
        val left = before.children.single { it.name == "Diamond" }.children.first()
        val circle = before.children.single { it.name == "Circle" }
        val leftSteps = steps(left)
        val circleSteps = steps(circle)
        leftSteps mustBe listOf("Diamond" to 0, "Left" to 0)

        val name = program.functionManager.getFunctions(true)
            .first { it.name == "name" && it.parentNamespace.name == "Circle" }
        program.runTransaction { name.setName("label", SourceType.USER_DEFINED) }
        val after = ClassTreeRoot(program.name, ClassHierarchy.of(program))

        steps(after.find(leftSteps) ?: fail("Diamond/Left is gone")) mustBe leftSteps
        val rebuilt = after.find(circleSteps) ?: fail("Circle is gone")
        rebuilt.children.map { it.name }.let { names ->
            ("label" in names).mustBeTrue("$names")
            ("name" in names).mustBeFalse()
        }
    }

    /** What keeps a selection through the filter: the tree finds a filtered node again by equals. */
    @ParameterizedTest
    @MethodSource("hellos")
    fun `a node equals its filtered clone and nothing else`(fixture: String) {
        load(fixture)
        val hierarchy = ClassHierarchy.of(program)
        val root = ClassTreeRoot(program.name, hierarchy).apply { loadAll(TaskMonitor.DUMMY) }
        val all = object : GTreeFilter {
            override fun acceptsNode(node: GTreeNode) = true
            override fun showFilterMatches() = true
        }
        val filtered = root.filter(all, TaskMonitor.DUMMY)
        val left = steps(root.children.single { it.name == "Diamond" }.children.first())
        val member = steps(root.children.single { it.name == "Circle" }.children.first { it is MemberNode })
        for (path in listOf(left, member)) {
            filtered.find(path) mustBe root.find(path)
            (ClassTreeRoot(program.name, hierarchy).find(path) == root.find(path)).mustBeFalse()
        }
    }

    /** What Navigate on Incoming selects for a location: the member there, under the class that lists it. */
    @ParameterizedTest
    @MethodSource("hellos")
    fun `an address finds its member's node, inverted too`(fixture: String) {
        load(fixture)
        val hierarchy = ClassHierarchy.of(program)
        for (inverted in listOf(false, true)) {
            val root = ClassTreeRoot(program.name, hierarchy, inverted = inverted)
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
        fun hellos() = stabsHellos()
    }
}
