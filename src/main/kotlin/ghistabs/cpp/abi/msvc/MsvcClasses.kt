package ghistabs.cpp.abi.msvc

import ghidra.app.cmd.data.rtti.Rtti1Model
import ghidra.app.cmd.data.rtti.Rtti3Model
import ghidra.app.cmd.data.rtti.Rtti4Model
import ghidra.app.cmd.data.rtti.VfTableModel
import ghidra.app.util.datatype.microsoft.DataValidationOptions
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.*
import ghistabs.cpp.abi.VtableRecord
import ghistabs.cpp.recover.AbiClasses
import ghistabs.cpp.recover.ClassRecovery
import ghistabs.diagnose.DiagnosticSink
import ghistabs.pointerAt
import ghistabs.toClass

/**
 * An entry of a Base Class Array: the class's type [descriptor], how many entries after it are its own bases
 * ([contained]), and how the most derived class holds it. [offset] is `mdisp`, which for a virtual base counts
 * from where its vbtable puts it: the vbtable the vbptr at [pdisp] points at, at byte [vdisp]. MSVC only says
 * whether a base is public, so the rest read as private.
 */
data class BaseEntry(
    val descriptor: Address,
    val contained: Int,
    override val isVirtual: Boolean,
    override val access: Access,
    override val offset: Long = 0,
    val pdisp: Long = -1,
    val vdisp: Long = 0,
) : BaseDecl {
    /** An entry by its Base Class Descriptor's `attributes`. */
    constructor(
        descriptor: Address,
        contained: Int,
        attributes: Int,
        mdisp: Long = 0,
        pdisp: Long = -1,
        vdisp: Long = 0,
    ) : this(
        descriptor,
        contained,
        isVirtual = attributes and Msvc.BCD_VBOFCONTOBJ != 0,
        access = if (attributes and Msvc.BCD_NONPUBLIC == 0) Access.PUBLIC else Access.PRIVATE,
        offset = mdisp,
        pdisp = pdisp,
        vdisp = vdisp,
    )

    /** The entry a Base Class Descriptor makes. */
    constructor(bcd: Rtti1Model) : this(
        bcd.rtti0Address,
        bcd.numBases,
        bcd.attributes,
        bcd.mDisp.toLong(),
        bcd.pDisp.toLong(),
        bcd.vDisp.toLong(),
    )
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
 * Classes off the MSVC RTTI Ghidra's RTTI analyzer laid, for [ClassRecovery]: their bases, off each Class
 * Hierarchy Descriptor's Base Class Array, and their vftables. Classes go by their type descriptor's address.
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

        /** Each vbtable, by where its vbptr sits in the class; filled by [readVbtables]. */
        val vbtables = mutableMapOf<Long, Address>()

        /** Where the Base Class Array's entries for a virtual base say vbptrs sit. */
        override val vbptrs get() = array.drop(1).filter { it.isVirtual }.mapTo(mutableSetOf()) { it.pdisp }

        override val virtualBases get() = array.drop(1).filter { it.isVirtual }.groupBy { it.descriptor }
            .map { (descriptor, entries) ->
                val at = entries.firstNotNullOfOrNull { e -> vbtables[e.pdisp]?.let { vbaseOffset(it, e) } }
                ClassBase(classAt(descriptor), isVirtual = true, entries.first().access, at)
            }
    }

    /** Where [entry]'s virtual base sits in the class whose vbptr points at [vbtable]. */
    private fun vbaseOffset(vbtable: Address, entry: BaseEntry) =
        runCatching { entry.pdisp + program.memory.getInt(vbtable.add(entry.vdisp)) + entry.offset }.getOrNull()

    // `mdisp` is no offset in the class for a virtual base.
    private fun BaseEntry.classOffset() = offset.takeUnless { isVirtual }

    /** The class with type descriptor [descriptor]; one known by its descriptor alone if no hierarchy names it. */
    private fun classAt(descriptor: Address) = classes.getOrPut(descriptor) {
        val ns = typeDescriptorClass(descriptor)
        RttiClass(ns, ns?.name ?: "?", emptyList())
    }

    fun recover(monitor: TaskMonitor = TaskMonitor.DUMMY): ClassRecovery.Result {
        val hierarchies = readHierarchies().toMap()
        classes += hierarchies
        val holders = readVftables()
        readVbtables(hierarchies.values, monitor)
        val read = AbiClasses(classes.values, hierarchies.values, holders)
        return ClassRecovery(program, Msvc, this).recover(read, monitor)
    }

    private fun readVbtables(hierarchies: Collection<RttiClass>, monitor: TaskMonitor) {
        val vbptrs: Map<ClassDecl, Set<Long>> = hierarchies.associateWith { it.vbptrs }.filterValues { it.isNotEmpty() }
        if (vbptrs.isEmpty()) return
        for ((cls, vbtables) in Vbtables(program, classes.values, this).read(vbptrs, monitor)) {
            (cls as RttiClass).vbtables += vbtables
        }
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

    /** The class of the type descriptor at [at], for a base with no hierarchy descriptor. */
    private fun typeDescriptorClass(at: Address) = symbols.getSymbols(at)
        .firstOrNull { it.name == Msvc.TYPE_DESCRIPTOR && !it.parentNamespace.isGlobal }
        ?.parentNamespace?.toClass()
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
