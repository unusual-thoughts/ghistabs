package ghistabs.cpp.abi.msvc

import ghidra.app.cmd.data.rtti.Rtti1Model
import ghidra.app.cmd.data.rtti.Rtti3Model
import ghidra.app.cmd.data.rtti.Rtti4Model
import ghidra.app.cmd.data.rtti.VfTableModel
import ghidra.app.util.datatype.microsoft.DataValidationOptions
import ghidra.program.model.address.Address
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.*
import ghistabs.cpp.ClassHierarchyRecords.Companion.readClassRecord
import ghistabs.cpp.ClassHierarchyRecords.Companion.writeClassRecord
import ghistabs.cpp.MemberAttrs.Companion.memberAttrs
import ghistabs.cpp.MemberAttrs.Companion.writeMember
import ghistabs.cpp.abi.*
import ghistabs.cpp.recover.NewSizeReader
import ghistabs.cpp.recover.StructorFinder
import ghistabs.cpp.recover.ThisClasses
import ghistabs.cpp.recover.fastcallToThiscall
import ghistabs.cpp.recover.sizeBounds
import ghistabs.cpp.recover.vptrOffsets
import ghistabs.diagnose.DiagnosticSink
import ghistabs.pointerAt
import ghistabs.toClass

/**
 * An entry of a Base Class Array: the class's type [descriptor], how many entries after it are its own bases
 * ([contained]), and how the most derived class holds it. [offset] is `mdisp`, which for a virtual base counts
 * from where its vbtable puts it. MSVC only says whether a base is public, so the rest read as private.
 */
data class BaseEntry(
    val descriptor: Address,
    val contained: Int,
    override val isVirtual: Boolean,
    override val access: Access,
    override val offset: Long = 0,
) : BaseDecl {
    /** An entry by its Base Class Descriptor's `attributes`. */
    constructor(descriptor: Address, contained: Int, attributes: Int, offset: Long = 0) : this(
        descriptor,
        contained,
        isVirtual = attributes and Msvc.BCD_VBOFCONTOBJ != 0,
        access = if (attributes and Msvc.BCD_NONPUBLIC == 0) Access.PUBLIC else Access.PRIVATE,
        offset = offset,
    )

    /** The entry a Base Class Descriptor makes. */
    constructor(bcd: Rtti1Model) : this(bcd.rtti0Address, bcd.numBases, bcd.attributes, bcd.mDisp.toLong())
}

/**
 * The direct bases in a Base Class Array: the class, then its bases in preorder, each followed by its own
 * [BaseEntry.contained]. A virtual base MSVC lists apart from the base that inherits it is dropped.
 */
fun directBases(array: List<BaseEntry>): List<BaseEntry> {
    val tops = generateSequence(1) { it + 1 + array[it].contained }.takeWhile { it < array.size }.toList()
    val inherited = tops.flatMapTo(mutableSetOf()) { i ->
        array.subList(i + 1, i + 1 + array[i].contained).map { it.descriptor }
    }
    return tops.map(array::get).filterNot { it.isVirtual && it.descriptor in inherited }.distinctBy { it.descriptor }
}

/**
 * The class a virtual function belongs to: the lowest common ancestor of the classes whose vftables
 * hold it ([holders]). That class may have no vftable, as an abstract base's is often not emitted; one
 * that has one and doesn't hold it means the linker folded separate overrides into one body
 * (`/OPT:ICF`). Null for those, and where no class is common.
 */
fun virtualOwner(holders: Set<ClassDecl>): ClassDecl? {
    val common = holders.map { it.ancestors + it }.reduce { a, b -> a intersect b }
    return common.singleOrNull { c -> common.none { it != c && it.derivesFrom(c) } }
        ?.takeIf { it in holders || it.vftables.isEmpty() }
}

/**
 * Classes off the MSVC RTTI Ghidra's RTTI analyzer laid: their bases and sizes for [ClassHierarchyRecords],
 * each virtual function moved into its class ([virtualOwners]) and marked virtual, and each constructor and
 * destructor ([ghistabs.cpp.recover.StructorFinder]) moved there and named, and then each unnamed function
 * that takes a `this` moved into the class its callers pass it objects of ([ThisClasses]). Classes go by their
 * type descriptor's address.
 */
class MsvcClasses(private val program: Program, sink: DiagnosticSink) : DiagnosticSink by sink {
    private val options = DataValidationOptions()
    private val symbols = program.symbolTable

    // Every class seen, by type descriptor: those with a hierarchy descriptor, and any other a table or a
    // Base Class Array names, which are known by nothing more than their descriptor.
    private val classes = mutableMapOf<Address, RttiClass>()

    /**
     * A class the RTTI describes, by its type descriptor: its namespace, if the analyzer made one, and its
     * Base Class Array ([array]), which lists every base, direct or not, after the class itself.
     */
    private inner class RttiClass(
        override val ns: Namespace?,
        override val name: String,
        private val array: List<BaseEntry>,
    ) : ClassDecl {
        override val bases by lazy {
            directBases(array).map { ClassBase(classAt(it.descriptor), it.isVirtual, it.access, it.classOffset()) }
        }
        override val ancestors by lazy { super.ancestors }

        // Filled by [readVftables].
        override val vftables = mutableListOf<VtableRecord>()
    }

    // `mdisp` is no offset in the class for a virtual base.
    private fun BaseEntry.classOffset() = offset.takeUnless { isVirtual }

    /** The class with type descriptor [descriptor]; one known by its descriptor alone if no hierarchy names it. */
    private fun classAt(descriptor: Address) = classes.getOrPut(descriptor) {
        val ns = typeDescriptorClass(descriptor)
        RttiClass(ns, ns?.name ?: "?", emptyList())
    }

    data class Result(
        val classes: Int,
        val owned: Int,
        val moved: Int,
        val shared: Int,
        val structors: Int,
        val sized: Int,
        val guessed: Int,
    )

    fun recover(monitor: TaskMonitor = TaskMonitor.DUMMY): Result {
        val hierarchies = readHierarchies().toMap()
        classes += hierarchies
        val holders = readVftables()
        val owners = holders.mapValues { (_, hs) -> virtualOwner(hs) }
        var moved = 0
        for ((func, owner) in owners) {
            if (owner != null && attach(func, owner)) moved++
        }
        val shared = owners.values.count { it == null }
        if (shared > 0) {
            debug("msvc-vfunction-shared", "$shared held by no one class", count = shared.toLong())
        }
        val structors = StructorFinder(program, classes.values, this).find(holders, Msvc, monitor)
        val named = structors.count { (func, structor) ->
            val cls = structor.first.ns?.toClass() ?: return@count false
            nameStructor(func, cls, structor.second)
        }
        val ctors = structors.filterValues { it.second == StructorRole.CONSTRUCTOR }.mapValues { it.value.first }
        val sizes = sizeClasses(NewSizeReader(program, Msvc, this).read(ctors, monitor))
        writeRecords(hierarchies.values, sizes)
        val guessed = ThisClasses(program, classes.values, this).guess(ctors, sizes, monitor)
        return Result(hierarchies.size, owners.size - shared, moved, shared, named, sizes.size, guessed)
    }

    private fun labelled(name: String) = symbols.getSymbols(name).iterator().asSequence().distinctBy { it.address }

    private fun readHierarchies() = labelled(Msvc.CLASS_HIERARCHY_DESCRIPTOR).mapNotNull { sym ->
        runCatching {
            val chd = Rtti3Model(program, sym.address, options)
            val array = chd.baseClassArray()
            val td = array.first().descriptor
            val ns = sym.parentNamespace.takeUnless { it.isGlobal } ?: typeDescriptorClass(td)
            td to RttiClass(ns, chd.rtti0Model.descriptorName, array)
        }.onFailure { warn("msvc-hierarchy-unread", "${sym.name}: ${it.message}", sym.address) }.getOrNull()
    }.toList()

    /** Each function a vftable slot holds, and the classes whose tables hold it. */
    private fun readVftables() = buildMap {
        // By each table's meta pointer label, which survives `RecoverClassesFromRTTIScript` renaming tables.
        val ptrSize = program.defaultPointerSize.toLong()
        for (sym in labelled(Msvc.VFTABLE_META_PTR)) {
            val at = sym.address.add(ptrSize)
            val table = runCatching { VfTableModel(program, at, options) }.getOrNull() ?: continue
            val cls = runCatching { table.rtti0Model.address }.getOrNull()?.let(::classAt) ?: continue
            cls.vftables += Msvc.recordAt(program, at)
            for (i in 0 until table.elementCount) {
                val func = slotFunction(table.getVirtualFunctionPointer(i), at) ?: continue
                getOrPut(func) { mutableSetOf() } += cls
            }
        }
    } as Map<Function, Set<RttiClass>>

    /** The function a slot points at, past a jump stub; not an import nor the shared `_purecall`. */
    private fun slotFunction(at: Address?, table: Address): Function? {
        val func = at?.let(program.functionManager::getFunctionAt) ?: return null.also {
            debug("msvc-vfunction-missing", "no function at $at", table)
        }
        val target = if (func.isThunk) func.getThunkedFunction(true) else func
        return target?.takeUnless { it.isExternal || "purecall" in it.name }
    }

    /** Marks [func] virtual unless recorded otherwise, and moves it into [cls] if it's global; whether it moved. */
    private fun attach(func: Function, cls: ClassDecl): Boolean {
        val entry = func.entryPoint
        if (program.memberAttrs(entry) == null) program.writeMember(entry, MemberAttrs(virt = VirtKind.VIRTUAL))
        val ns = cls.ns?.toClass() ?: return false
        return func.parentNamespace.isGlobal && runCatching { func.parentNamespace = ns }
            .onFailure { warn("msvc-vfunction-unmoved", "${func.name} -> ${ns.getName(true)}: $it", entry) }
            .isSuccess
    }

    /**
     * Each class's size range, off what it is [allocated] with and its bases' and vptrs' offsets. A struct
     * shorter than an exact size grows to it, but none is made: `RecoverClassesFromRTTIScript` would take
     * it for the layout rather than work one out.
     */
    private fun sizeClasses(allocated: Map<ClassDecl, Long>): Map<ClassDecl, LongRange> {
        val all = classes.values.toList()
        val bounds = sizeBounds(all, vptrOffsets(all, program), allocated, program.defaultPointerSize.toLong())
        for ((cls, size) in bounds) {
            val exact = size.singleOrNull() ?: continue
            val ns = cls.ns?.toClass() ?: continue
            val struct = classStruct(ns)?.takeUnless { it.isNotYetDefined || it.length >= exact } ?: continue
            runCatching { struct.growStructure((exact - struct.length).toInt()) }
                .onFailure { warn("msvc-struct-ungrown", "${ns.getName(true)} -> $exact: $it") }
        }
        return bounds.filterValues { it.first > 0 }
    }

    private fun nameStructor(func: Function, cls: GhidraClass, role: StructorRole): Boolean {
        val name = Msvc.structorFor(role, func).displayName(cls.name)
        return runCatching {
            val moves = func.parentNamespace.isGlobal
            if (moves) func.parentNamespace = cls
            val renames = func.parentNamespace == cls && func.symbol.source == SourceType.DEFAULT
            if (renames) func.setName(name, SourceType.ANALYSIS)
            val retyped = func.parentNamespace == cls && func.fastcallToThiscall()
            moves || renames || retyped
        }.onFailure {
            warn("msvc-structor-unnamed", "${func.name} -> ${cls.getName(true)}::$name: $it", func.entryPoint)
        }
            .getOrDefault(false)
    }

    /** Writes each class's record over an earlier run's, so a rerun finds `RecoverClassesFromRTTIScript`'s struct. */
    private fun writeRecords(classes: Collection<ClassDecl>, sizes: Map<ClassDecl, LongRange>) {
        val entries = classes.mapNotNull { cls ->
            ClassHierarchyRecords.entryOf(cls, cls.ns?.toClass()?.let(::classStructId), sizes[cls])
        }
        program.writeClassRecord(program.readClassRecord().orEmpty() + entries)
    }

    /** The class of the type descriptor at [at], for a base with no hierarchy descriptor. */
    private fun typeDescriptorClass(at: Address) = symbols.getSymbols(at)
        .firstOrNull { it.name == Msvc.TYPE_DESCRIPTOR && !it.parentNamespace.isGlobal }
        ?.parentNamespace?.toClass()

    /** The class's struct where `RecoverClassesFromRTTIScript` files it. */
    private fun classStruct(ns: GhidraClass) =
        program.dataTypeManager.getDataType(ClassNaming.vftableCategory(ns), ns.name) as? Structure

    private fun classStructId(ns: GhidraClass): Long? {
        val struct = classStruct(ns) ?: return null
        return program.dataTypeManager.getID(struct).takeIf { it >= 0 }
    }
}

/** The Base Class Array a Class Hierarchy Descriptor points at: the class itself first, then its bases. */
fun Rtti3Model.baseClassArray(): List<BaseEntry> = rtti2Model.let { bca ->
    (0..<rtti1Count).map { BaseEntry(bca.getRtti1Model(it)) }
}

/** The offset of the subobject the vftable at [vftable] serves, by its complete object locator; null if it has none. */
fun Program.msvcSubobjectOffset(vftable: Address): Int? {
    val meta = runCatching { vftable.subtract(defaultPointerSize.toLong()) }.getOrNull() ?: return null
    if (symbolTable.getSymbols(meta).none { it.name == Msvc.VFTABLE_META_PTR }) return null
    val col = pointerAt(meta) ?: return null
    return runCatching { Rtti4Model(this, col, DataValidationOptions()).vbTableOffset }.getOrNull()
}
