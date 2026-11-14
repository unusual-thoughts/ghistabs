package ghicpp.abi.msvc

import ghicpp.ClassDecl
import ghicpp.ClassStructsFixtureTest
import ghicpp.abi.isPrimaryTableSymbol
import ghicpp.analyzers.MsvcClassAnalyzer
import ghicpp.hierarchy.*
import ghicpp.qualifiedName
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.data.FunctionDefinition
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghidrakt.diagnose.DummySink
import ghidrakt.runTransaction
import ghidrakt.test.mustBe
import ghidrakt.test.mustBeNull
import ghidrakt.test.mustBeTrue
import org.junit.jupiter.api.Test

/**
 * `features/hello.cc` under the MSVC ABI, stripped, through the whole analysis: the class pass lays each class
 * struct off the RTTI and the constructors. `Label` derives from `Rect`, itself a `Shape`, and from `Named`;
 * `Up` and `Down` derive virtually from `Core`, and `Both` from them. Built twice, by cl and by clang-cl, which lay
 * the classes alike and place the functions differently.
 */
abstract class MsvcClassStructsIntegrationTest(fixture: String, private val rectDeletingDestructor: String) :
    ClassStructsFixtureTest(fixture, compiler = "windows") {
    @Test
    fun `each vptr is the class's own, typed to the table it points at, its bases split around it`() {
        program.layout("Label") mustBe listOf(
            0 to "vfptr: Label_vftable_for_Rect *",
            4 to "_base_Rect: Rect_fields_4_24",
            24 to "vfptr: Label_vftable_for_Named *",
            28 to "_base_Named: Named_fields_4_12",
            36 to "Label_data: Label_data",
        )
        program.classStruct("Rect_vftable").definedComponents.map { it.fieldName } mustBe
            listOf(rectDeletingDestructor, "vfunction2", "vfunction3", "vfunction4")
    }

    @Test
    fun `of a class's qualified vftable symbols, the one its locator gives offset 0 is its own`() {
        // `Label`'s tables, for `Rect` at +0 and `Named` at +24.
        val tables = MsvcRttiParser(program, DummySink).parse(TaskMonitor.DUMMY).recorded
            .single { it.qualifiedName == "Label" }.vftables.sortedBy { it.vfptrOffset(program) }
        tables.map { it.vfptrOffset(program) } mustBe listOf(0L, 24L)
        val symbols = program.runTransaction {
            tables.zip(listOf("Rect", "Named")).map { (table, base) ->
                program.symbolTable.createLabel(table.addressPoint, "??_7Label@@6B$base@@@", SourceType.IMPORTED)
            }
        }
        try {
            symbols.map { Msvc.isPrimaryVtable(it.name) } mustBe listOf(false, false)
            symbols.map { isPrimaryTableSymbol(it, Msvc) } mustBe listOf(true, false)
        } finally {
            program.runTransaction { symbols.forEach { it.delete() } }
        }
    }

    @Test
    fun `a class's own fields are where its constructors store them`() {
        program.classStruct("Rect_data").definedComponents.map { it.offset to it.fieldName } mustBe
            listOf(0 to "field_0x10", 4 to "field_0x14")
    }

    @Test
    fun `a virtual base is laid where the vbtable a constructor stores says`() {
        program.layout("Up") mustBe listOf(
            0 to "vfptr: Up_vftable *",
            4 to "_fields: Up_fields_4_12",
            12 to "vfptr: Up_vftable_for_Core *",
            16 to "_vbase_: Core_fields_4_8",
        )
        // Past the vtordisp `Down`'s override of `f` puts in front of it.
        program.layout("Both").filter { (at, _) -> at >= 28 } mustBe listOf(
            28 to "vfptr: Both_vftable_for_Core *",
            32 to "_vbase_Core: Core_fields_4_8",
        )
    }

    @Test
    fun `the vftables put each virtual base where the vbtable does`() {
        // What a class no function here builds, so that no vbtable is found, has its virtual bases placed by.
        val classes = MsvcRttiParser(program, DummySink).parse(TaskMonitor.DUMMY).recorded
        fun ClassDecl.tables() = vftables.map { it.vfptrOffset(program)!! to it.slots(program).size }
        val placed = classes.filter { c -> c.virtualBases.none { it.cls.vbptrs.any() } }.mapNotNull { c ->
            val vbases = c.virtualBases.takeIf { it.isNotEmpty() } ?: return@mapNotNull null
            vbaseOffsetsByVftables(vbases.map { it.cls.tables() }, c.tables())?.let { c.qualifiedName to it }
        }.toMap()
        // `Left` and `Right`'s `Base` has no vftable, to say where it sits. The others' vbtables, which the
        // analysis read, put it where the tests above see it laid.
        placed mustBe mapOf("Up" to listOf(12L), "Down" to listOf(12L), "Both" to listOf(28L))
        for (cls in placed.keys) {
            val vbase = (program.dataTypeManager.getDataType("/ClassDataTypes/$cls/$cls") as Structure)
                .definedComponents.single { it.fieldName.startsWith("_vbase_") }
            vbase.comment.orEmpty().contains("by the vbtable") mustBe true
        }
    }

    @Test
    fun `a base with virtual bases is embedded as its non-virtual part, its vbptr in it`() {
        program.layout("Both").first { (at, _) -> at == 4 } mustBe (4 to "_base_Up: Up_fields_4_12")
        val selfBase = program.dataTypeManager.getDataType("/ClassDataTypes/Up/Up/!internal/Up_fields_4_12")
        (selfBase as Structure).definedComponents.first().let { (it.fieldName to (it.dataType is Pointer)) } mustBe
            ("vbptr" to true)
    }

    @Test
    fun `a class whose only vftable is its virtual base's has the base laid off the vbtable`() {
        // `Down` adds no virtual, so its only vftable is `Core`'s, stored through the vbtable.
        program.layout("Down") mustBe listOf(
            0 to "vbptr: int *",
            12 to "vfptr: Down_vftable *",
            16 to "_vbase_: Core_fields_4_8",
        )
    }

    @Test
    fun `a function several vftables hold has one definition, for signature updates to reach them all`() {
        // `Up` inherits `Core::f`, its second slot in both tables.
        (program.secondSlot("Up_vftable_for_Core") === program.secondSlot("Core_vftable")) mustBe true
        program.classStruct("Up_vftable_for_Core").getComponent(1).fieldName mustBe
            program.secondSlot("Core_vftable").name
    }

    @Test
    fun `constructors the decompiler shows no this return for are told from destructors by their calls`() {
        // The unoptimised callers leave the constructors' `this` return unread.
        program.layout("Circle") mustBe listOf(
            0 to "vfptr: Circle_vftable *",
            4 to "_base_: Shape_fields_4_16",
            16 to "Circle_data: Circle_data",
        )
    }

    @Test
    fun `a base with no vftable is built by what its deriving class's constructor calls on it`() {
        // `Left` and `Right` store no vftable; the linker folded their constructors into one.
        program.layout("Diamond").map { (at, field) -> at to field.substringBefore(':') } mustBe listOf(
            0 to "vfptr",
            4 to "_base_Named",
            12 to "_base_Left",
            20 to "_base_Right",
            28 to "Diamond_data",
        )
        program.layout("Right") mustBe listOf(0 to "vbptr: int *")
    }

    @Test
    fun `a method's this is the class struct, not a placeholder Ghidra adds at the root`() {
        program.dataTypeManager.getDataType("/Label").mustBeNull()
        val method = program.functionManager.getFunctions(true).first {
            it.parentNamespace.name == "Label" && it.callingConventionName == "__thiscall"
        }
        (method.getParameter(0).dataType as Pointer).dataType.pathName mustBe "/ClassDataTypes/Label/Label"
    }

    @Test
    fun `no method is left the __fastcall Ghidra picks when this is the only register argument`() {
        val edx = program.language.getRegister("EDX")
        program.functionManager.getFunctions(true).filter { f ->
            f.parentNamespace is GhidraClass && f.callingConventionName == "__fastcall" &&
                f.parameters.none { it.register?.baseRegister == edx }
        }.map { it.getName(true) } mustBe emptyList()
    }

    @Test
    fun `a virtual returning a double still returns it in ST0 once it is __thiscall`() {
        val area = program.functionManager.getFunctions(true).single { it.getName(true) == "Circle::vfunction2" }
        area.callingConventionName mustBe "__thiscall"
        area.returnType.name mustBe "double"
        area.`return`.register?.name mustBe "ST0"
        area.parameters.map { it.name } mustBe listOf("this")
    }

    @Test
    fun `a virtual function Ghidra typed __fastcall is __thiscall again once the class pass places it`() {
        val vfunction = program.functionManager.getFunctions(true).first {
            it.name.startsWith("vfunction") && it.callingConventionName == "__thiscall" && it.parameterCount == 1
        }
        program.runTransaction { vfunction.setCallingConvention("__fastcall") }
        program.runTransaction { MsvcClassAnalyzer().added(program, program.memory, TaskMonitor.DUMMY, MessageLog()) }
        vfunction.callingConventionName mustBe "__thiscall"
    }

    @Test
    fun `applying a method's signature to its slot retypes it in every vftable holding it`() {
        // `Core::f`, the second slot of `Core`'s table and of `Up`'s for it.
        val f = program.functionManager.getFunctions(true).single { it.getName(true) == "Core::vfunction2" }
        program.runTransaction {
            f.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED)
            program.applySignatureToSlots(f) mustBe 1
        }
        for (table in listOf("Core_vftable", "Up_vftable_for_Core")) {
            (program.secondSlot(table) as FunctionDefinition).returnType.name mustBe "int"
        }
    }

    @Test
    fun `the window shows which constructor or destructor a member is`() {
        // The class pass names `Circle`'s two constructors; this build's destructors stay `FUN_`s.
        val circle = ClassHierarchy.of(program, hasStabs = false).classes.single { it.qualifiedName == "Circle" }
        circle.members.filter { it.msvcStructor != null }.map { it.label } mustBe
            listOf("Circle(int) [constructor]", "Circle(undefined8) [constructor]")
        MsvcStructor.ofName("~Circle", "Circle") mustBe MsvcStructor.DESTRUCTOR
        MsvcStructor.ofName("`scalar_deleting_destructor'", "Circle") mustBe MsvcStructor.SCALAR_DELETING_DESTRUCTOR
        MsvcStructor.ofMangled("??_ECircle@@UAEPAXI@Z") mustBe MsvcStructor.VECTOR_DELETING_DESTRUCTOR
    }

    @Test
    fun `renaming a virtual slot renames every override of it and its field in every vftable`() = program.rolledBack {
        val h = ClassHierarchy.of(program, hasStabs = false)
        val slots = VirtualSlots(program, h)
        // `Rect::area`, the second slot of `Rect`'s table: `Shape`'s pure `area`, `Circle`'s and `Label`'s too.
        val area = slots.target(slots.slotsOf(h.classes.single { it.qualifiedName == "Rect" })[1])!!
        val done = slots.rename(area, "area")
        done.skipped mustBe emptyList()
        done.functions mustBe 3
        for (table in listOf("Shape_vftable", "Circle_vftable", "Rect_vftable", "Label_vftable_for_Rect")) {
            program.classStruct(table).getComponent(1).fieldName mustBe "area"
        }
        program.functionManager.getFunctions(true).filter { it.name == "area" }.map { it.parentNamespace.name }
            .sorted() mustBe listOf("Circle", "Label", "Rect")
        program.classStruct("Core_vftable").getComponent(1).fieldName mustBe "vfunction2"
    }

    @Test
    fun `applying slot names names a class's slots, or a method's, after the functions they hold`() =
        program.rolledBack {
            val h = ClassHierarchy.of(program, hasStabs = false)
            val slots = VirtualSlots(program, h)
            val rect = h.classes.single { it.qualifiedName == "Rect" }
            // `Rect::perim`, its fourth slot, inherited by `Label`.
            val perim = slots.target(slots.slotsOf(rect)[3])!!
            perim.setName("perim", SourceType.USER_DEFINED)
            slots.applyNames(slots.slotsOf(rect)).fields mustBe 1
            program.classStruct("Rect_vftable").getComponent(3).fieldName mustBe "perim"
            program.classStruct("Label_vftable_for_Rect").getComponent(3).fieldName mustBe "vfunction4"
            slots.applyNames(slots.slotsOf(perim)).fields mustBe 1
            program.classStruct("Label_vftable_for_Rect").getComponent(3).fieldName mustBe "perim"
        }

    @Test
    fun `renaming a class renames its own fields' struct and the field holding it`() = program.rolledBack {
        val h = ClassHierarchy.of(program, hasStabs = false)
        program.renameClass(h, h.classes.single { it.qualifiedName == "Label" }, "Tag") mustBe emptyList()
        program.layout("Tag").last() mustBe (36 to "Tag_data: Tag_data")
    }

    @Test
    fun `making a split base virtual and back renames its field and keeps the layout`() = program.rolledBack {
        val h = ClassHierarchy.of(program, hasStabs = false)
        val (label, rect) = listOf("Label", "Rect").map { n -> h.classes.single { it.qualifiedName == n } }
        val before = program.layout("Label")
        program.respellBase(label, rect, isVirtual = true, baseCount = 2).mustBeTrue()
        program.layout("Label") mustBe before.map { (at, f) -> at to f.replace("_base_Rect:", "_vbase_Rect:") }
        program.respellBase(label, rect, isVirtual = false, baseCount = 2).mustBeTrue()
        program.layout("Label") mustBe before
    }

    @Test
    fun `renaming a destructor slot names each class's scalar deleting destructor`() = program.rolledBack {
        val h = ClassHierarchy.of(program, hasStabs = false)
        val slots = VirtualSlots(program, h)
        fun cls(name: String) = h.classes.single { it.qualifiedName == name }
        val dtor = slots.target(slots.slotsOf(cls("Rect"))[0])!!
        slots.rename(dtor, "~Rect").skipped mustBe emptyList()
        for (name in listOf("Rect", "Circle", "Label")) {
            // cl folds some classes' into one, outside any class: named the same, all the same.
            slots.target(slots.slotsOf(cls(name))[0])!!.name mustBe "`scalar_deleting_destructor'"
        }
        program.classStruct("Shape_vftable").getComponent(0).fieldName mustBe "`scalar_deleting_destructor'"
    }

    /** Runs [edit] in a transaction it then rolls back, so the other tests see the program as analysed. */
    private fun Program.rolledBack(edit: () -> Unit) {
        val tx = startTransaction("rolled back")
        try {
            edit()
        } finally {
            endTransaction(tx, false)
        }
    }

    private fun Program.secondSlot(table: String) = (classStruct(table).getComponent(1).dataType as Pointer).dataType

    private fun Program.classStruct(name: String) = dataTypeManager.allStructures.asSequence()
        .single {
            it.name == name && it.categoryPath.path.startsWith("/ClassDataTypes/") && "!internal" !in it.pathName
        }
}

/** `hello` built by cl; `Rect`'s deleting destructor, its vftable's first slot, is where cl puts it. */
class ClMsvcClassStructsIntegrationTest : MsvcClassStructsIntegrationTest("hello_msvc.exe", "FUN_00402150")

/** `hello` built by clang-cl. */
class ClangClMsvcClassStructsIntegrationTest : MsvcClassStructsIntegrationTest("hello_msvc_clang.exe", "FUN_00401fc0")
