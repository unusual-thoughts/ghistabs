package ghistabs.cpp.abi

import ghidra.app.cmd.data.rtti.Rtti1Model
import ghidra.app.cmd.data.rtti.Rtti3Model
import ghidra.app.cmd.data.rtti.Rtti4Model
import ghidra.app.cmd.data.rtti.VfTableModel
import ghidra.app.util.datatype.microsoft.DataValidationOptions
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.*
import ghistabs.cpp.ClassHierarchyRecords.Companion.readClassRecord
import ghistabs.cpp.ClassHierarchyRecords.Companion.writeClassRecord
import ghistabs.cpp.MemberAttrs.Companion.memberAttrs
import ghistabs.cpp.MemberAttrs.Companion.writeMember
import ghistabs.diagnose.DiagnosticSink
import ghistabs.pointerAt
import ghistabs.toClass

/**
 * One entry of a class's RTTI Base Class Array: the class [descriptor] that describes it, how many entries after
 * it are that class's own bases ([contained]), how the most derived class holds it, and where in it: [offset],
 * the descriptor's `mdisp`, which for a virtual base is from wherever its vbtable puts it instead.
 */
data class BaseEntry(
    val descriptor: Address,
    val contained: Int,
    val isVirtual: Boolean,
    val isPublic: Boolean,
    val offset: Int = 0,
) {
    /** An entry by its Base Class Descriptor's `attributes`. */
    constructor(descriptor: Address, contained: Int, attributes: Int, offset: Int = 0) : this(
        descriptor,
        contained,
        isVirtual = attributes and Msvc.BCD_VBOFCONTOBJ != 0,
        isPublic = attributes and Msvc.BCD_NONPUBLIC == 0,
        offset = offset,
    )

    /** The entry a Base Class Descriptor makes. */
    constructor(bcd: Rtti1Model) : this(bcd.rtti0Address, bcd.numBases, bcd.attributes, bcd.mDisp)
}

/**
 * The direct bases among a Base Class Array, whose first entry is the class itself and the rest its
 * bases in preorder, each followed by the [BaseEntry.contained] entries of its own. Stepping over those
 * leaves the direct bases, plus any virtual base MSVC hoisted out from under the base that inherits it,
 * which is dropped for being one of that base's.
 */
fun directBases(array: List<BaseEntry>): List<BaseEntry> {
    val tops = generateSequence(1) { it + 1 + array[it].contained }.takeWhile { it < array.size }.toList()
    val inherited = tops.flatMapTo(mutableSetOf()) { i ->
        array.subList(i + 1, i + 1 + array[i].contained).map { it.descriptor }
    }
    return tops.map(array::get).filterNot { it.isVirtual && it.descriptor in inherited }.distinctBy { it.descriptor }
}

/**
 * The class each virtual function belongs to, given the classes whose vftables hold it ([holders]),
 * every class's bases, direct or not ([ancestors]), and the classes with a vftable at all
 * ([hasVftable]). Null for a function no one class explains.
 *
 * A function is its holders' lowest common ancestor's: one a derived class does not override sits in
 * its table and in every table below, so the class that introduced it is the one all its holders
 * derive from. That ancestor need not hold it itself, when it has no vftable to hold it in: an
 * abstract base's table is often never emitted, its pure slots and all. One that does have a table,
 * and holds something else there, means the holders' copies are separate overrides the linker folded
 * into one body (`/OPT:ICF`), as it does across unrelated classes, which have no common ancestor at
 * all. `RecoverClassesFromRTTIScript` gives those to whichever class it reaches first.
 */
fun <K, F> virtualOwners(holders: Map<F, Set<K>>, ancestors: (K) -> Set<K>, hasVftable: (K) -> Boolean): Map<F, K?> =
    holders.mapValues { (_, hs) ->
        val common = hs.map { ancestors(it) + it }.reduce { a, b -> a intersect b }
        common.singleOrNull { c -> common.none { it != c && c in ancestors(it) } }
            ?.takeIf { it in hs || !hasVftable(it) }
    }

/**
 * Class records and members for a binary whose only C++ information is the MSVC RTTI that Ghidra's
 * `Windows x86 PE RTTI Analyzer` has laid and labelled: each class's direct bases off its Class Hierarchy
 * Descriptor, written to [ClassHierarchyRecords], and each virtual function off the vftables, moved into
 * the class it belongs to ([virtualOwners]) and marked virtual for the Class Hierarchy window, and each
 * constructor and destructor, found by the vptrs it stores ([structors]), moved there and named.
 *
 * Classes are keyed by their type descriptor's address, which every RTTI record names a class by.
 */
class MsvcClasses(private val program: Program, sink: DiagnosticSink) : DiagnosticSink by sink {
    private val options = DataValidationOptions()
    private val symbols = program.symbolTable

    // The classes with a vftable of their own, which [readVftables] collects.
    private val tableClasses = mutableSetOf<Address>()

    /** A class the RTTI describes: its namespace, if the analyzer made one, and its Base Class Array. */
    private class RttiClass(
        val descriptor: Address,
        val ns: Namespace?,
        val name: String,
        val bases: List<BaseEntry>,
    ) {
        val ancestors = bases.drop(1).mapTo(mutableSetOf()) { it.descriptor }
        val directBases by lazy { directBases(bases) }
    }

    // Each vftable, by the class it serves and where in that class's object its vptr sits.
    private val tables = mutableMapOf<Address, Pair<Address, Long>>()

    data class Result(
        val classes: Int,
        val owned: Int,
        val moved: Int,
        val shared: Int,
        val structors: Int,
        val sized: Int,
    )

    fun recover(monitor: TaskMonitor = TaskMonitor.DUMMY): Result {
        val classes = readHierarchies().associateBy { it.descriptor }
        val holders = readVftables()
        val owners = virtualOwners(holders, { classes[it]?.ancestors.orEmpty() }, { it in tableClasses })
        var moved = 0
        for ((func, owner) in owners) {
            val cls = owner?.let(classes::get) ?: continue
            if (attach(func, cls)) moved++
        }
        val shared = owners.values.count { it == null }
        if (shared > 0) {
            debug("msvc-vfunction-shared", "$shared held by no one class", count = shared.toLong())
        }
        val structors = findStructors(classes, holders, monitor)
        val named = structors.count { (func, structor) ->
            val cls = classes[structor.first]?.ns?.toClass() ?: return@count false
            nameStructor(func, cls, structor.second)
        }
        val ctors = structors.filterValues { it.second == StructorKind.CONSTRUCTOR }.mapValues { it.value.first }
        val sized = sizeStructs(classes, NewSizeReader<Address>(program, this).read(ctors, monitor))
        writeRecords(classes)
        return Result(classes.size, owners.size - shared, moved, shared, named, sized)
    }

    private fun labelled(name: String) = symbols.getSymbols(name).iterator().asSequence().distinctBy { it.address }

    private fun readHierarchies() = labelled(Msvc.CLASS_HIERARCHY_DESCRIPTOR).mapNotNull { sym ->
        runCatching {
            val chd = Rtti3Model(program, sym.address, options)
            val bca = chd.rtti2Model
            val array = (0..<chd.rtti1Count).map { BaseEntry(bca.getRtti1Model(it)) }
            val td = array.first().descriptor
            RttiClass(td, sym.parentNamespace.takeUnless { it.isGlobal }, chd.rtti0Model.descriptorName, array)
        }.onFailure { warn("msvc-hierarchy-unread", "${sym.name}: ${it.message}", sym.address) }.getOrNull()
    }.toList()

    /** Each function a vftable slot holds, and the classes whose tables hold it. */
    private fun readVftables() = buildMap {
        // By the meta pointer in front of each table, whose label `RecoverClassesFromRTTIScript` keeps when
        // it renames a class's tables after the bases they serve (`vftable_for_Signable`).
        val ptrSize = program.defaultPointerSize.toLong()
        for (sym in labelled(Msvc.VFTABLE_META_PTR)) {
            val at = sym.address.add(ptrSize)
            val table = runCatching { VfTableModel(program, at, options) }.getOrNull() ?: continue
            val cls = runCatching { table.rtti0Model.address }.getOrNull() ?: continue
            tableClasses += cls
            program.msvcSubobjectOffset(at)?.let { tables[at] = cls to it.toLong() }
            for (i in 0 until table.elementCount) {
                val func = slotFunction(table.getVirtualFunctionPointer(i), at) ?: continue
                getOrPut(func) { mutableSetOf() } += cls
            }
        }
    } as Map<Function, Set<Address>>

    /**
     * The function a slot points at, through an incremental-link jump stub. Not an imported one, which
     * no class here owns, nor `_purecall`, which every abstract class's pure slots share.
     */
    private fun slotFunction(at: Address?, table: Address): Function? {
        val func = at?.let(program.functionManager::getFunctionAt) ?: return null.also {
            debug("msvc-vfunction-missing", "no function at $at", table)
        }
        val target = if (func.isThunk) func.getThunkedFunction(true) else func
        return target?.takeUnless { it.isExternal || "purecall" in it.name }
    }

    /**
     * Move [func] into [cls]'s namespace if nothing has placed it anywhere yet, and mark it virtual
     * unless something already recorded what it is. Whether it moved.
     */
    private fun attach(func: Function, cls: RttiClass): Boolean {
        val entry = func.entryPoint
        if (program.memberAttrs(entry) == null) program.writeMember(entry, MemberAttrs(virt = VirtKind.VIRTUAL))
        val ns = cls.ns?.toClass() ?: return false
        return func.parentNamespace.isGlobal && runCatching { func.parentNamespace = ns }
            .onFailure { warn("msvc-vfunction-unmoved", "${func.name} -> ${ns.getName(true)}: $it", entry) }
            .isSuccess
    }

    /** Each class's constructors, destructor and deleting destructor ([structors]), off the vptrs they store. */
    private fun findStructors(
        classes: Map<Address, RttiClass>,
        holders: Map<Function, Set<Address>>,
        monitor: TaskMonitor,
    ): Map<Function, Pair<Address, StructorKind>> {
        val reading = VptrStoreReader(program, tables, this).read(holders.keys, monitor)
        return structors(
            reading.stores,
            holders,
            { reading.thisCalls[it].orEmpty() },
            { classes[it]?.ancestors.orEmpty() },
            Msvc.constructorsReturnThis,
        )
    }

    /**
     * Give each class's struct the size [sizeBounds] finds, off the sizes it is allocated with
     * ([allocated]), its bases' offsets and its vptrs': a struct there is none of is made, empty, in the
     * class's category, where `RecoverClassesFromRTTIScript` and shift-D look for it, and one shorter is
     * grown. How many it made or grew.
     */
    private fun sizeStructs(classes: Map<Address, RttiClass>, allocated: Map<Address, Long>): Int {
        val bases = classes.mapValues { (_, cls) ->
            cls.directBases.filterNot { it.isVirtual }.map { it.descriptor to it.offset.toLong() }
        }
        val vptrs = tables.values.groupBy({ it.first }, { it.second }).mapValues { (_, at) -> at.max() }
        val bounds = sizeBounds(bases, vptrs, allocated, program.defaultPointerSize.toLong())
        return bounds.count { (descriptor, size) ->
            val ns = classes[descriptor]?.ns?.toClass() ?: return@count false
            size.size > 0 && sizeStruct(ns, size)
        }
    }

    private fun sizeStruct(ns: GhidraClass, bounds: SizeBounds): Boolean {
        val dtm = program.dataTypeManager
        val size = bounds.size.toInt()
        val how = when {
            bounds.exact != null -> "Size from `operator new` and the RTTI"
            else -> "At least as large as the RTTI says its vptrs and bases reach"
        }
        val struct = dtm.getDataType(ClassNaming.vftableCategory(ns), ns.name) as? Structure
        return runCatching {
            when {
                struct == null -> {
                    val stub = StructureDataType(ClassNaming.vftableCategory(ns), ns.name, size, dtm)
                    stub.description = how
                    dtm.addDataType(stub, DataTypeConflictHandler.KEEP_HANDLER)
                    true
                }

                struct.isNotYetDefined -> {
                    struct.setLength(size)
                    struct.description = how
                    true
                }

                struct.length < size -> {
                    struct.growStructure(size - struct.length)
                    true
                }

                else -> {
                    if (bounds.exact != null && struct.length > size) {
                        debug("msvc-struct-oversized", "${ns.getName(true)}: ${struct.length} > new's $size")
                    }
                    false
                }
            }
        }.onFailure { warn("msvc-struct-unsized", "${ns.getName(true)} -> $size: $it") }.getOrDefault(false)
    }

    private fun nameStructor(func: Function, cls: GhidraClass, kind: StructorKind): Boolean {
        val name = when (kind) {
            StructorKind.CONSTRUCTOR -> cls.name

            StructorKind.DESTRUCTOR -> "~${cls.name}"

            StructorKind.DELETING_DESTRUCTOR ->
                if (func.testsVectorFlag()) Msvc.VECTOR_DELETING_DESTRUCTOR else Msvc.SCALAR_DELETING_DESTRUCTOR
        }
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

    /** A vector deleting destructor tests its flags for bit 2, which says an array is going. */
    private fun Function.testsVectorFlag() = program.listing.getInstructions(body, true).any { insn ->
        insn.pcode.any { op -> op.opcode == PcodeOp.INT_AND && op.inputs.any { it.isConstant && it.offset == 2L } }
    }

    /**
     * Each class's entry, over its own from an earlier run: a one-shot after `RecoverClassesFromRTTIScript`
     * finds the struct the script filed. Other classes' entries are kept.
     */
    private fun writeRecords(classes: Map<Address, RttiClass>) {
        val entries = classes.values.mapNotNull { cls ->
            val ns = cls.ns?.toClass() ?: return@mapNotNull null
            val bases = cls.directBases.map { b ->
                val base = classes[b.descriptor]
                val baseNs = base?.ns?.toClass() ?: typeDescriptorClass(b.descriptor)
                ClassHierarchyRecords.Base(
                    baseNs?.id,
                    if (baseNs == null) base?.name ?: "?" else null,
                    b.isVirtual,
                    if (b.isPublic) Access.PUBLIC else Access.PRIVATE,
                )
            }
            ns.id to ClassHierarchyRecords.Entry(classStructId(ns), bases)
        }
        program.writeClassRecord(program.readClassRecord().orEmpty() + entries)
    }

    /** A base with no hierarchy descriptor of its own still has its type descriptor labelled in its class. */
    private fun typeDescriptorClass(at: Address) = symbols.getSymbols(at)
        .firstOrNull { it.name == Msvc.TYPE_DESCRIPTOR && !it.parentNamespace.isGlobal }
        ?.parentNamespace?.toClass()

    /** The struct `RecoverClassesFromRTTIScript` or a user filed for the class, where shift-D finds it. */
    private fun classStructId(ns: GhidraClass): Long? {
        val dtm = program.dataTypeManager
        val struct = dtm.getDataType(ClassNaming.vftableCategory(ns), ns.name) as? Structure ?: return null
        return dtm.getID(struct).takeIf { it >= 0 }
    }
}

/**
 * Where in the complete object the subobject an MSVC vftable at [vftable] serves sits, as its complete object
 * locator states it: 0 for the class's primary table. Null for any other table, no `vftable_meta_ptr` before it.
 */
fun Program.msvcSubobjectOffset(vftable: Address): Int? {
    val meta = runCatching { vftable.subtract(defaultPointerSize.toLong()) }.getOrNull() ?: return null
    if (symbolTable.getSymbols(meta).none { it.name == Msvc.VFTABLE_META_PTR }) return null
    val col = pointerAt(meta) ?: return null
    return runCatching { Rtti4Model(this, col, DataValidationOptions()).vbTableOffset }.getOrNull()
}
