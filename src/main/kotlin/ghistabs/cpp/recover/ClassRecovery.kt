package ghistabs.cpp.recover

import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.*
import ghistabs.cpp.ClassHierarchyRecords.Companion.readClassRecord
import ghistabs.cpp.ClassHierarchyRecords.Companion.writeClassRecord
import ghistabs.cpp.MemberAttrs.Companion.memberAttrs
import ghistabs.cpp.MemberAttrs.Companion.writeMember
import ghistabs.cpp.abi.CxxAbi
import ghistabs.cpp.abi.StructorRole
import ghistabs.cpp.abi.VtableRecord
import ghistabs.diagnose.DiagnosticSink
import ghistabs.toClass

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
 * The classes an ABI's own records describe, as its class pass read them: [classes], every one seen; those
 * whose bases it knows, to record ([recorded]); and each function a vftable slot holds, with the classes
 * whose tables hold it ([holders]).
 */
class AbiClasses(
    val classes: Collection<ClassDecl>,
    val recorded: Collection<ClassDecl>,
    val holders: Map<Function, Set<ClassDecl>>,
)

/**
 * What a class pass does once an ABI's records have given it the classes ([AbiClasses]): each virtual
 * function moved into the class that introduced it ([virtualOwner]) and marked virtual, each constructor
 * and destructor ([StructorFinder]) moved there and named, each class sized off its allocations and layout
 * ([sizeBounds]), and the classes written to [ClassHierarchyRecords].
 */
class ClassRecovery(private val program: Program, private val abi: CxxAbi, sink: DiagnosticSink) :
    DiagnosticSink by sink {
    data class Result(
        val classes: Int,
        val owned: Int,
        val moved: Int,
        val shared: Int,
        val structors: Int,
        val sized: Int,
        val laid: Int,
    )

    fun recover(read: AbiClasses, monitor: TaskMonitor): Result {
        val owners = read.holders.mapValues { (_, hs) -> virtualOwner(hs) }
        val structors = StructorFinder(program, read.classes, this).find(read.holders, abi, monitor)
        var moved = 0
        for ((func, owner) in owners) {
            val holders = read.holders.getValue(func)
            val name = if (func in structors) null else owner?.let { slotName(func, it, holders) }
            if (owner != null && attach(func, owner, name)) moved++
        }
        val shared = owners.values.count { it == null }
        if (shared > 0) {
            debug("class-vfunction-shared", "$shared held by no one class", count = shared.toLong())
        }
        val named = structors.count { (func, structor) ->
            val cls = structor.first.ns?.toClass() ?: return@count false
            nameStructor(func, cls, structor.second)
        }
        val ctors = structors.filterValues { it.second == StructorRole.CONSTRUCTOR }.mapValues { it.value.first }
        val stores = program.constructorStores(ctors, monitor)
        val reached = stores.mapValues { (_, at) -> at.maxOf { (offset, size) -> offset + size }.toLong() }
        val sizes = sizeClasses(read.classes, NewSizeReader(program, abi, this).read(ctors, monitor), reached)
        val laid = ClassLayouts(program, abi, this).layAll(read.recorded, stores)
        val placed = owners.entries.mapNotNull { (f, owner) -> owner?.let { f to it } } +
            structors.map { (f, structor) -> f to structor.first }
        writeRecords(read.recorded, placed.groupBy({ it.second }, { it.first }), ctors.keys)
        return Result(read.recorded.size, owners.size - shared, moved, shared, named, sizes.size, laid)
    }

    /**
     * Marks [func] virtual unless recorded otherwise, and [claim]s it for [cls] under [name]; whether it moved.
     */
    private fun attach(func: Function, cls: ClassDecl, name: String?): Boolean {
        val entry = func.entryPoint
        if (program.memberAttrs(entry) == null) program.writeMember(entry, MemberAttrs(virt = VirtKind.VIRTUAL))
        val ns = cls.ns?.toClass() ?: return false
        return runCatching { claim(func, ns, name).first }
            .onFailure { warn("class-vfunction-unmoved", "${func.name} -> ${ns.getName(true)}: $it", entry) }
            .getOrDefault(false)
    }

    /**
     * `vfunctionN`, as `RecoverClassesFromRTTIScript` names a virtual: [func]'s slot, from 1, in [owner]'s
     * vftables, or where it has none, in those of the classes holding it ([holders]). Where that class has
     * several tables, `vfunctionN_for_Base` after the base the table serves, as the script names it.
     */
    private fun slotName(func: Function, owner: ClassDecl, holders: Set<ClassDecl>): String? {
        for (cls in listOf(owner) + holders) {
            for (record in cls.vftables) {
                val slot = record.slots(program).indexOfFirst { at ->
                    program.functionManager.getFunctionAt(at)?.let { it.getThunkedFunction(true) ?: it } == func
                }
                if (slot < 0) continue
                val base = if (cls.vftables.size > 1) cls.servedBase(record, program) else null
                return "$VFUNCTION${slot + 1}" + base?.let { "_for_${it.name}" }.orEmpty()
            }
        }
        return null
    }

    /**
     * Moves [func] into [ns] where it's global or [guessed], and names it [name] where it's [guessed], as an
     * analysis: what this pass concludes is inferred, though the later analysis's. The labels an analysis left
     * at its entry in [ns] under either name go first, as `RecoverClassesFromRTTIScript` labels a function in
     * each class it holds it in, or they collide. Whether it moved, and whether it was renamed.
     */
    private fun claim(func: Function, ns: GhidraClass, name: String?): Pair<Boolean, Boolean> {
        val guessed = func.guessed()
        val moves = (func.parentNamespace.isGlobal || guessed) && func.parentNamespace.id != ns.id
        val renames = guessed && name != null && func.name != name
        if (moves || renames) {
            program.symbolTable.getSymbols(func.entryPoint)
                .filter { it != func.symbol && it.parentNamespace.id == ns.id && it.source == SourceType.ANALYSIS }
                .filter { it.name == func.name || it.name == name }
                .forEach { it.delete() }
        }
        if (moves) func.parentNamespace = ns
        if (renames) func.setName(name, SourceType.ANALYSIS)
        return moves to renames
    }

    /**
     * Whether [this]'s name and class are a guess this pass may replace with its own, being the later analysis:
     * it has no name, or one an analysis gave it in a class, as `RecoverClassesFromRTTIScript` names what it
     * places. A name a user or the debug info gave stays, and one an analysis gave a global function, such as
     * Function ID's.
     */
    private fun Function.guessed() = symbol.source == SourceType.DEFAULT ||
        (symbol.source == SourceType.ANALYSIS && parentNamespace is GhidraClass)

    /**
     * Each class's size range, off what it is [allocated] with, its bases' and vptrs' offsets and how far its
     * constructors store ([reached]). Each class
     * gets a struct of its exact size, or else its least, where `RecoverClassesFromRTTIScript` files one: a
     * stub of undefined bytes when it has none, and its own grown when shorter.
     */
    private fun sizeClasses(
        classes: Collection<ClassDecl>,
        allocated: Map<ClassDecl, Long>,
        reached: Map<ClassDecl, Long>,
    ): Map<ClassDecl, LongRange> {
        val all = classes.toList()
        val bounds = sizeBounds(all, vptrOffsets(all, program), allocated, program.defaultPointerSize.toLong(), reached)
        val sized = bounds.filterValues { it.first > 0 }
        for ((cls, size) in sized) {
            val ns = cls.ns?.toClass() ?: continue
            val length = size.first.toInt()
            runCatching {
                when (val struct = program.classStruct(ns)) {
                    null -> program.dataTypeManager.addDataType(
                        StructureDataType(ClassNaming.vftableCategory(ns), ns.name, length),
                        DataTypeConflictHandler.KEEP_HANDLER,
                    )

                    else if struct.length < length -> struct.growStructure(length - struct.length)
                }
            }.onFailure { warn("class-struct-unsized", "${ns.getName(true)} -> $length: $it") }
        }
        return sized
    }

    /** Names a structor the ABI's way, or `Foo` and `~Foo` where the ABI can't tell the variant. */
    private fun nameStructor(func: Function, cls: GhidraClass, role: StructorRole): Boolean {
        val name = abi.structorFor(role, func)?.displayName(cls.name)
            ?: if (role == StructorRole.CONSTRUCTOR) cls.name else "~${cls.name}"
        return runCatching {
            val (moves, renames) = claim(func, cls, name)
            val retyped = func.parentNamespace.id == cls.id && func.fastcallToThiscall()
            moves || renames || retyped
        }.onFailure {
            warn("class-structor-unnamed", "${func.name} -> ${cls.getName(true)}::$name: $it", func.entryPoint)
        }.getOrDefault(false)
    }

    /**
     * Writes each class's record, with the [methods] this pass placed in it and which are [constructors], over
     * an earlier run's, so a rerun finds `RecoverClassesFromRTTIScript`'s struct.
     */
    private fun writeRecords(
        classes: Collection<ClassDecl>,
        methods: Map<ClassDecl, List<Function>>,
        constructors: Set<Function>,
    ) {
        val entries = classes.mapNotNull { cls ->
            val own = methods[cls].orEmpty()
            ClassHierarchyRecords.entryOf(
                cls,
                cls.ns?.toClass()?.let(::classStructId),
                own.map { it.entryPoint.offset },
                own.filter { it in constructors }.map { it.entryPoint.offset },
            )
        }
        program.writeClassRecord(program.readClassRecord().orEmpty() + entries)
    }

    private fun classStructId(ns: GhidraClass): Long? {
        val struct = program.classStruct(ns) ?: return null
        return program.dataTypeManager.getID(struct).takeIf { it >= 0 }
    }

    private companion object {
        const val VFUNCTION = "vfunction"
    }
}

/** The class's struct where `RecoverClassesFromRTTIScript` files it. */
fun Program.classStruct(ns: GhidraClass) =
    dataTypeManager.getDataType(ClassNaming.vftableCategory(ns), ns.name) as? Structure

/**
 * The base of this class whose subobject [record]'s vptr sits in: the first direct non-virtual base at its
 * offset, else the virtual base there.
 */
fun ClassDecl.servedBase(record: VtableRecord, program: Program): ClassDecl? {
    val at = record.vfptrOffset(program) ?: return null
    return bases.firstOrNull { !it.isVirtual && (it.offset ?: 0L) == at }?.cls
        ?: virtualBases.firstOrNull { it.offset == at }?.cls
}
