package ghistabs.cpp.recover

import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.ClassDecl
import ghistabs.cpp.ClassHierarchyRecords
import ghistabs.cpp.ClassHierarchyRecords.Companion.readClassRecord
import ghistabs.cpp.ClassHierarchyRecords.Companion.writeClassRecord
import ghistabs.cpp.ClassNaming
import ghistabs.cpp.MemberAttrs
import ghistabs.cpp.MemberAttrs.Companion.memberAttrs
import ghistabs.cpp.MemberAttrs.Companion.writeMember
import ghistabs.cpp.VirtKind
import ghistabs.cpp.abi.CxxAbi
import ghistabs.cpp.abi.StructorRole
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
    )

    fun recover(read: AbiClasses, monitor: TaskMonitor): Result {
        val owners = read.holders.mapValues { (_, hs) -> virtualOwner(hs) }
        var moved = 0
        for ((func, owner) in owners) {
            if (owner != null && attach(func, owner)) moved++
        }
        val shared = owners.values.count { it == null }
        if (shared > 0) {
            debug("class-vfunction-shared", "$shared held by no one class", count = shared.toLong())
        }
        val structors = StructorFinder(program, read.classes, this).find(read.holders, abi, monitor)
        val named = structors.count { (func, structor) ->
            val cls = structor.first.ns?.toClass() ?: return@count false
            nameStructor(func, cls, structor.second)
        }
        val ctors = structors.filterValues { it.second == StructorRole.CONSTRUCTOR }.mapValues { it.value.first }
        val sizes = sizeClasses(read.classes, NewSizeReader(program, abi, this).read(ctors, monitor))
        writeRecords(read.recorded, sizes)
        return Result(read.recorded.size, owners.size - shared, moved, shared, named, sizes.size)
    }

    /** Marks [func] virtual unless recorded otherwise, and moves it into [cls] if it's global; whether it moved. */
    private fun attach(func: Function, cls: ClassDecl): Boolean {
        val entry = func.entryPoint
        if (program.memberAttrs(entry) == null) program.writeMember(entry, MemberAttrs(virt = VirtKind.VIRTUAL))
        val ns = cls.ns?.toClass() ?: return false
        return func.parentNamespace.isGlobal && runCatching { func.parentNamespace = ns }
            .onFailure { warn("class-vfunction-unmoved", "${func.name} -> ${ns.getName(true)}: $it", entry) }
            .isSuccess
    }

    /**
     * Each class's size range, off what it is [allocated] with and its bases' and vptrs' offsets. A struct
     * shorter than an exact size grows to it, but none is made: `RecoverClassesFromRTTIScript` would take
     * it for the layout rather than work one out.
     */
    private fun sizeClasses(
        classes: Collection<ClassDecl>,
        allocated: Map<ClassDecl, Long>,
    ): Map<ClassDecl, LongRange> {
        val all = classes.toList()
        val bounds = sizeBounds(all, vptrOffsets(all, program), allocated, program.defaultPointerSize.toLong())
        for ((cls, size) in bounds) {
            val exact = size.singleOrNull() ?: continue
            val ns = cls.ns?.toClass() ?: continue
            val struct = classStruct(ns)?.takeUnless { it.isNotYetDefined || it.length >= exact } ?: continue
            runCatching { struct.growStructure((exact - struct.length).toInt()) }
                .onFailure { warn("class-struct-ungrown", "${ns.getName(true)} -> $exact: $it") }
        }
        return bounds.filterValues { it.first > 0 }
    }

    /** Names a structor the ABI's way, or `Foo` and `~Foo` where the ABI can't tell the variant. */
    private fun nameStructor(func: Function, cls: GhidraClass, role: StructorRole): Boolean {
        val name = abi.structorFor(role, func)?.displayName(cls.name)
            ?: if (role == StructorRole.CONSTRUCTOR) cls.name else "~${cls.name}"
        return runCatching {
            val moves = func.parentNamespace.isGlobal
            if (moves) func.parentNamespace = cls
            val renames = func.parentNamespace == cls && func.symbol.source == SourceType.DEFAULT
            if (renames) func.setName(name, SourceType.ANALYSIS)
            val retyped = func.parentNamespace == cls && func.fastcallToThiscall()
            moves || renames || retyped
        }.onFailure {
            warn("class-structor-unnamed", "${func.name} -> ${cls.getName(true)}::$name: $it", func.entryPoint)
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

    /** The class's struct where `RecoverClassesFromRTTIScript` files it. */
    private fun classStruct(ns: GhidraClass) =
        program.dataTypeManager.getDataType(ClassNaming.vftableCategory(ns), ns.name) as? Structure

    private fun classStructId(ns: GhidraClass): Long? {
        val struct = classStruct(ns) ?: return null
        return program.dataTypeManager.getID(struct).takeIf { it >= 0 }
    }
}
