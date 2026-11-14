package ghicpp.recover

import ghicpp.*
import ghicpp.ClassHierarchyRecords.Companion.readClassRecord
import ghicpp.ClassHierarchyRecords.Companion.writeClassRecord
import ghicpp.MemberAttrs.Companion.recordPlaced
import ghicpp.abi.RttiParser
import ghicpp.abi.StructorRole
import ghicpp.dissect.*
import ghidra.framework.options.Options
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunctionDBUtil
import ghidra.program.model.pcode.HighVariable
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghidra.util.task.TaskMonitor.DUMMY
import ghidrakt.*
import ghidrakt.diagnose.DiagnosticSink

/**
 * What a class pass does once an ABI's records have given it the classes ([RttiParser], [ClassPassInput]): each virtual
 * function moved into the class that introduced it ([introducingClass]) and marked virtual, each constructor
 * and destructor ([ThisFunctionDissector]) moved there and named, each class sized off its allocations and layout
 * ([sizeBounds]), what a constructor inlined after `operator new` builds typed as its class ([typeAllocations]), and
 * the classes written to [ClassHierarchyRecords]. [vfptrModel] says whether a class
 * struct splits a base around the vptr it takes over ([ClassStructFiller]).
 */
class ClassPass(
    private val program: Program,
    private val parser: RttiParser,
    sink: DiagnosticSink,
    options: Options? = null,
) : OptionContainer(),
    DiagnosticSink by sink {
    val vfptrModel: VfptrModel by VfptrModel.OPTION

    /** Whether a field a constructor fills in a counted loop or with `memset` is an array ([ThisFunctionDissector]). */
    var fillArrays: Boolean by FILL_ARRAYS

    /** Whether a constructor inlined after `operator new` is read for its class's size, bases and fields. */
    var inlinedConstructors: Boolean by INLINED_CONSTRUCTORS

    init {
        options?.let { import(it) }
    }

    data class Result(
        val classes: Int,
        val owned: Int,
        val moved: Int,
        val shared: Int,
        val structors: Int,
        val sized: Int,
        val filled: Int,
    ) {
        /** The constructors and destructors the pass found, and what they call, for a later pass to read. */
        var found: FoundStructors? = null
            internal set
    }

    private val abi = parser.abi

    /** Runs the pass over the classes [parser] reads. */
    fun run(monitor: TaskMonitor = DUMMY): Result {
        val cache = DissectionCache(fillArrays, abi.operatorNewNames.takeIf { inlinedConstructors }.orEmpty())
        // The parser dissecting the storers as it parses reads them so, and this reads them off it.
        (parser as? DissectingParser)?.cache = cache
        val read = parser.parse(monitor)
        stubStructs(read.classes)
        val owners = read.holders.mapValues { (_, hs) -> introducingClass(hs) }
        val inspector = ThisFunctionDissector(program, read.classes, this, cache)
        val found = inspector.find(read.holders, abi, monitor)
        val structors = found.roles
        var moved = 0
        monitor.initialize(owners.size.toLong(), "Moving virtual functions into their classes")
        for ((func, owner) in owners) {
            monitor.increment()
            val holders = read.holders.getValue(func)
            val name = if (func in structors) null else owner?.let { slotName(func, it, holders) }
            if (owner != null && attach(func, owner, name)) moved++
        }
        val shared = owners.values.count { it == null }
        if (shared > 0) {
            debug("class-vfunction-shared", "$shared held by no one class", count = shared.toLong())
        }
        monitor.initialize(structors.size.toLong(), "Naming constructors and destructors")
        val named = structors.count { (func, structor) ->
            monitor.increment()
            val cls = structor.first.ns?.toClass() ?: return@count false
            nameStructor(func, cls, structor.second)
        }
        val ctors = found.constructors
        val stores = found.constructorStores
        // A class with a vptr is aligned at least as a pointer, which a trailing `bool` leaves it short of.
        val reached = stores.mapValues { (cls, at) ->
            val end = at.maxOfOrNull { (offset, dt) -> offset + dt.length }?.toLong() ?: 0L
            val align = if (cls.vftables.isEmpty()) 1L else program.defaultPointerSize.toLong()
            end.alignedTo(align)
        }
        val called = AllocationSizeFinder(program, abi, this).read(ctors, monitor)
        val allocated = (called.keys + found.inlinedSizes.keys).associateWith { cls ->
            maxOf(called[cls] ?: 0L, found.inlinedSizes[cls] ?: 0L)
        }
        val sizes = sizeClasses(read.classes, allocated, reached)
        monitor.message = "Filling class structs"
        val filled = ClassStructFiller(program, abi, this, vfptrModel).fillAll(read.recorded, stores)
        program.typeAllocations(found, this, monitor)
        val placed = owners.entries.mapNotNull { (f, owner) -> owner?.let { f to it } } +
            structors.map { (f, structor) -> f to structor.first }
        monitor.message = "Recording classes"
        for ((func, _) in placed) program.recordPlaced(func, structors[func]?.second, virtual = func in owners)
        writeRecords(read.recorded)
        return Result(read.recorded.size, owners.size - shared, moved, shared, named, sizes.size, filled)
            .also { it.found = found }
    }

    /**
     * Moves the virtual function [func] into [cls]'s namespace, renamed to [name] if one is given. Once it is in
     * the class, its calling convention is fixed to take `this` ([fixMethodConvention]); [run] records it virtual
     * ([recordPlaced]). Returns whether it was moved.
     */
    private fun attach(func: Function, cls: ClassDecl, name: String?): Boolean {
        val entry = func.entryPoint
        val ns = cls.ns?.toClass() ?: return false
        val moved = runCatching { claim(func, ns, name).first }
            .onFailure { warn("class-vfunction-unmoved", "${func.name} -> ${ns.getName(true)}: $it", entry) }
            .getOrDefault(false)
        if (func.parentNamespace.id == ns.id) {
            runCatching { func.fixMethodConvention(takesThis = true) }
                .onFailure { warn("class-vfunction-convention", "${func.name} -> ${ns.getName(true)}: $it", entry) }
        }
        return moved
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
     * An empty struct for each class with none, where `RecoverClassesFromRTTIScript` files one, before any
     * function moves in: a `__thiscall` function landing in a class with no struct makes Ghidra add a
     * placeholder in the class's parent category, `/<Class>` for a global one, which its lookup then prefers.
     */
    private fun stubStructs(classes: Collection<ClassDecl>) {
        for (ns in classes.mapNotNull { it.ns?.toClass() }) {
            if (program.classStruct(ns) != null) continue
            runCatching {
                program.dataTypeManager.addDataType(
                    StructureDataType(ClassNaming.vftableCategory(ns), ns.name, 0),
                    DataTypeConflictHandler.KEEP_HANDLER,
                )
            }.onFailure { warn("class-struct-unstubbed", "${ns.getName(true)}: $it") }
        }
    }

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
                program.sizeClassStruct(ns, length)
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
            val retyped = func.parentNamespace.id == cls.id && func.fixMethodConvention(takesThis = true)
            moves || renames || retyped
        }.onFailure {
            warn("class-structor-unnamed", "${func.name} -> ${cls.getName(true)}::$name: $it", func.entryPoint)
        }.getOrDefault(false)
    }

    /** Writes each class's record over an earlier run's, so a rerun finds `RecoverClassesFromRTTIScript`'s struct. */
    private fun writeRecords(classes: Collection<ClassDecl>) {
        val entries = classes.mapNotNull { cls ->
            ClassHierarchyRecords.entryOf(cls, cls.ns?.toClass()?.let(::classStructId))
        }
        program.writeClassRecord(program.readClassRecord().orEmpty() + entries)
    }

    private fun classStructId(ns: GhidraClass): Long? {
        val struct = program.classStruct(ns) ?: return null
        return program.dataTypeManager.getID(struct).takeIf { it >= 0 }
    }

    companion object {
        private const val VFUNCTION = "vfunction"
        val FILL_ARRAYS = BoolOption(
            "Arrays from fill loops",
            "Type a field a constructor fills in a loop counted down from a constant, as x86's rep stos does, " +
                "or with memset of a constant size, as an array",
            true,
        )
        val INLINED_CONSTRUCTORS = BoolOption(
            "Constructors inlined after new",
            "Read the vtables, fields and member constructors that code stores into or calls on what " +
                "operator new(size) returns as a constructor inlined there: the last vtable stored is the class " +
                "built, of that size, each one before it a base of the next",
            true,
        )
    }
}

/**
 * Types the variable each [InlinedConstruction] builds its object in as a pointer to the class it builds: what
 * `operator new` returns, in the function that inlines the constructor, as `RecoverClassesFromRTTIScript` types
 * `this`. A variable whose type a user or the debug info locked stays as it is.
 */
fun Program.typeAllocations(found: FoundStructors, sink: DiagnosticSink, monitor: TaskMonitor = DUMMY): Int {
    var typed = 0
    val inlined = found.inlinedByFunction
    decompileEach(inlined.keys, monitor, "Typing the objects constructors inlined after new build") { func, high ->
        val calls = high.pcodeOps.asSequence().filter { it.opcode == PcodeOp.CALL }.associateBy { it.seqnum.target }
        for (construction in inlined.getValue(func)) {
            val struct = construction.built.ns?.toClass()?.let(::classStruct) ?: continue
            val symbol = calls[construction.at]?.output?.namedVariable()?.symbol ?: continue
            if (symbol.isTypeLocked) continue
            val type = PointerDataType(struct, dataTypeManager)
            if (symbol.dataType.isEquivalent(type)) continue
            runCatching { HighFunctionDBUtil.updateDBVariable(symbol, null, type, SourceType.ANALYSIS) }
                .onSuccess { typed++ }
                .onFailure { sink.warn("allocation-untyped", "${func.name} -> ${struct.name} *: $it", construction.at) }
        }
    }
    return typed
}

/** How many casts or copies [namedVariable] follows. */
private const val MAX_COPIES = 4

/** The variable [this] lands in: its own, or where the decompiler casts or copies it into a named one. */
private fun Varnode.namedVariable(depth: Int = 0): HighVariable? {
    high?.takeIf { it.symbol != null }?.let { return it }
    if (depth >= MAX_COPIES) return null
    return descendants.asSequence()
        .filter { it.opcode == PcodeOp.CAST || it.opcode == PcodeOp.COPY }
        .firstNotNullOfOrNull { it.output?.namedVariable(depth + 1) }
}
