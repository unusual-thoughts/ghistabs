package ghicpp.ooa

import ghicpp.abi.gcc2.Gcc2Thunks
import ghicpp.abi.generic.PlainVtables
import ghicpp.abi.itanium.Itanium
import ghicpp.abi.msvc.Msvc
import ghicpp.abi.functionSlots
import ghicpp.abi.isSlotCode
import ghicpp.dissect.DECOMPILE_TIMEOUT_SECONDS
import ghicpp.dissect.PointerInto
import ghicpp.dissect.decompileEach
import ghicpp.dissect.pointerInto
import ghicpp.dissect.directCallee
import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.VoidDataType
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.HighFunctionDBUtil
import ghidra.program.model.pcode.HighVariable
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghidrakt.plus
import ghidrakt.pointerAt
import ghidrakt.runTransaction
import ghidrakt.useWith
import java.io.Writer

/**
 * One of OOAnalyzer's initial facts, as its `oorules/facts.pl` declares them: a [predicate] and its [args],
 * each already a Prolog term.
 */
data class OoFact(val predicate: String, val args: List<String>) {
    override fun toString() = "$predicate(${args.joinToString(", ")})."

    companion object {
        fun of(predicate: String, vararg args: Any) = OoFact(predicate, args.map(::term))

        /** A Prolog term for [value]: a number in hex as OOAnalyzer writes them, a quoted atom, a list. */
        fun term(value: Any): String = when (value) {
            is Term -> value.text
            is Address -> hex(value.offset)
            is Long -> hex(value)
            is Int -> hex(value.toLong())
            is String -> "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"
            is List<*> -> value.joinToString(", ", "[", "]") { term(it!!) }
            else -> error("no Prolog term for $value")
        }

        private fun hex(v: Long) = when {
            v < 0 -> "-0x" + (-v).toString(16)
            v == 0L -> "0"
            else -> "0x" + v.toString(16)
        }
    }
}

/** A term written as is: an unquoted atom such as a symbolic value's `sv_…` or `type_Heap`. */
@JvmInline
value class Term(val text: String)

/** The ABIs OOAnalyzer's rules tell apart, by where `this` comes in: `fileInfo/4`'s third argument. */
enum class OoAbi(val ptrSize: Int) {
    MSVC_32(4),
    MSVC_64(8),
    SYSV_32(4),
    SYSV_64(8),
    ;

    val isMsvc get() = this == MSVC_32 || this == MSVC_64

    /** Where `this` comes in, as the rules spell the parameter: a register, or the first stack argument. */
    val thisParam: Any get() = when (this) {
        MSVC_32 -> Term("ecx")
        MSVC_64 -> Term("rcx")
        SYSV_32 -> 0L
        SYSV_64 -> Term("rdi")
    }

    /** The calling convention that takes `this` there, as `oorules/util.pl`'s `thisPtrParam/2` names it. */
    val thisCall: String get() = when (this) {
        MSVC_32 -> "__thiscall"
        MSVC_64 -> "__x64call"
        SYSV_32 -> "__sysv32call"
        SYSV_64 -> "__sysv64call"
    }

    companion object {
        fun of(program: Program): OoAbi {
            val msvc = program.compilerSpec.compilerSpecID.idAsString == "windows"
            val wide = program.defaultPointerSize == 8
            return when {
                msvc && wide -> MSVC_64
                msvc -> MSVC_32
                wide -> SYSV_64
                else -> SYSV_32
            }
        }
    }
}

/**
 * Writes what a program's code says of its objects as OOAnalyzer's initial facts, for its Prolog rules
 * (`ooprolog --facts`) to recover the classes from, as Pharos' `ooanalyzer` would have written them. Read
 * off Ghidra's listing and decompiler, not off anything our class recovery concluded: the vptr stores, the
 * pointer tables they store, the virtual calls, the calls and their `this`, the accesses through `this`,
 * `operator new` and `delete`, thunks, the pure virtual stub, and MSVC's RTTI where Ghidra laid it.
 *
 * A symbolic value (`sv_…`) is a decompiled variable of one function, `sv_<function>_<n>`, or a constant
 * offset into one, `sv_<function>_<n>_<offset>`, with a `thisPtrOffset/3` between the two. The facts the
 * rules never read (`thisPtrDefinition`, `funcReturn`, `callReturn`) and those this has no analysis for
 * (`uninitializedReads`, `possibleVBTableWrite`, `symbolClass`) are left out.
 */
class OoFactExporter(private val program: Program, private val monitor: TaskMonitor = TaskMonitor.DUMMY) {
    val abi = OoAbi.of(program)
    private val ptrSize = abi.ptrSize
    private val memory = program.memory
    private val functions = program.functionManager
    private val facts = linkedSetOf<OoFact>()
    private val dtm = program.dataTypeManager

    private fun add(predicate: String, vararg args: Any) {
        facts += OoFact.of(predicate, *args)
    }

    /** The entry points of the pure virtual stubs, [isPureVirtual]. */
    private var purecalls: Set<Long> = emptySet()

    /** Every fact, in the order they were found: functions by address, each one's in its p-code's order. */
    fun export(): List<OoFact> {
        facts.clear()
        add("fileInfo", program.executableMD5.orEmpty().uppercase(), program.name, Term(abi.name), ptrSize)
        val vftables = sortedSetOf<Long>()
        val calls = mutableListOf<ThisCall>()
        val methods = mutableSetOf<Address>()
        val all = (functions.getFunctions(true) as Iterable<Function>).filter { !it.isExternal }
        purecalls = all.filter(::isPureVirtual).map { it.entryPoint.offset }.toSet()
        for (f in all) {
            if (f.entryPoint.offset in purecalls) add("purecall", f.entryPoint)
            if (f.isThunk) {
                f.getThunkedFunction(false)?.takeIf { !it.isExternal }
                    ?.let { add("thunk", f.entryPoint, it.entryPoint) }
            }
        }
        program.decompileEach(all, monitor, "Exporting OOAnalyzer facts") { f, high ->
            FunctionFacts(f, high).run {
                read()
                if (thisVar != null && !returnsValue) returnsSelfOnceTyped(f, high)
                vftables += stored
                calls += thisCalls
                if (thisVar != null) methods += f.entryPoint
            }
        }
        orderFacts(methods, calls)
        if (abi.isMsvc) rtti(vftables)
        vftables.forEach(::vftableEntries)
        return facts.toList()
    }

    fun write(out: Writer) {
        out.write("% Prolog facts for OOAnalyzer, exported by ghicpp from ${program.name}.\n")
        export().forEach { out.write("$it\n") }
        out.write("% Object fact exporting complete.\n")
    }

    // --- per function --------------------------------------------------------------------------------------

    /** A call on [thisPtr], what it passes as `this`, at [at] in [caller], of [callee] (its entry, dethunked). */
    class ThisCall(val at: Address, val caller: Address, val callee: Address?, val thisPtr: String?, val kind: Kind) {
        enum class Kind { METHOD, NEW, DELETE }
    }

    private inner class FunctionFacts(val f: Function, val high: HighFunction) {
        private val ids = mutableMapOf<HighVariable, Int>()
        val stored = mutableSetOf<Long>()
        val thisCalls = mutableListOf<ThisCall>()

        /** The variable `this` comes in as, where the function reads it at [OoAbi.thisParam]. */
        var thisVar: HighVariable? = null

        private fun sv(root: HighVariable, offset: Long = 0): String {
            val n = ids.getOrPut(root) { ids.size }
            val base = "sv_${f.entryPoint.offset.toString(16)}_$n"
            if (offset == 0L) return base
            val derived = base + "_" + (if (offset < 0) "m" + (-offset).toString(16) else offset.toString(16))
            add("thisPtrOffset", Term(base), offset, Term(derived))
            return derived
        }

        private fun sv(p: PointerInto) = sv(p.root, p.offset)

        fun read() {
            params()
            val ops = high.pcodeOps.asSequence().toList().sortedBy { it.seqnum }
            val returns = mutableListOf<Boolean>()
            for (op in ops) {
                when (op.opcode) {
                    PcodeOp.CALL -> call(op)

                    PcodeOp.CALLIND -> virtualCall(op)

                    PcodeOp.STORE -> store(op)

                    PcodeOp.LOAD -> access(op, op.getInput(1), op.output?.size)

                    PcodeOp.RETURN -> if (op.numInputs > 1) {
                        returns += thisVar != null && op.getInput(1).pointerInto() == PointerInto(thisVar, 0)
                    }
                }
            }
            returnsValue = returns.isNotEmpty()
            if (returns.isNotEmpty() && returns.all { it }) add("returnsSelf", f.entryPoint)
        }

        /** Whether the decompiler gave the function a return value at all, so that [read] could test it. */
        var returnsValue = false

        /** `funcParameter/3` for each input the decompiler found it reading, and the conventions they allow. */
        private fun params() {
            val inputs = high.pcodeOps.asSequence().flatMap { it.inputs.asSequence() }
                .filter { it.isInput && it.high != null }.distinctBy { it.address to it.size }.toList()
            val positions = inputs.mapNotNull { vn -> positionOf(vn)?.let { it to vn } }
            for ((pos, vn) in positions) {
                add("funcParameter", f.entryPoint, pos, Term(sv(vn.high)))
                if (pos == abi.thisParam) thisVar = vn.high
            }
            conventions(positions.map { it.first }.toSet())
        }

        private fun conventions(read: Set<Any>) {
            val conventions = when (abi) {
                OoAbi.MSVC_32 -> {
                    val ecx = Term("ecx") in read
                    val edx = Term("edx") in read
                    when {
                        read.isEmpty() -> listOf("__cdecl", "__stdcall", "__thiscall", "__fastcall")
                        edx -> listOf("__fastcall")
                        ecx -> listOf("__thiscall", "__fastcall")
                        else -> listOf("__cdecl", "__stdcall")
                    }
                }

                // One convention per ABI, and its `this` only where the function reads it.
                else -> listOf(abi.thisCall).filter { thisVar != null || read.isEmpty() }
            }
            conventions.forEach { add("callingConvention", f.entryPoint, it) }
        }

        private fun call(op: PcodeOp) {
            val at = op.seqnum.target
            val callee = high.directCallee(op)
            add("callTarget", at, f.entryPoint, op.getInput(0).address)
            val args = (1 until op.numInputs).map { op.getInput(it) }
            var thisArg: String? = null
            args.forEachIndexed { i, arg ->
                val pos = callee?.let { argPosition(it, i) } ?: return@forEachIndexed
                val p = arg.pointerInto() ?: return@forEachIndexed
                val term = sv(p)
                add("callParameter", at, f.entryPoint, pos, Term(term))
                if (pos == abi.thisParam) thisArg = term
            }
            val names = callee?.let(::namesOf).orEmpty()
            when {
                names.any { it in OPERATOR_NEW } -> {
                    val out = op.output?.high?.let { sv(it) }
                    add("insnCallsNew", at, f.entryPoint, Term(out ?: "invalid"))
                    val size = args.firstOrNull()?.takeIf { it.isConstant }?.offset
                    if (out != null && size != null) {
                        add("thisPtrAllocation", at, f.entryPoint, Term(out), Term("type_Heap"), size)
                    }
                    thisCalls += ThisCall(at, f.entryPoint, callee?.entryPoint, out, ThisCall.Kind.NEW)
                }

                names.any { it in OPERATOR_DELETE } -> {
                    val freed = args.firstOrNull()?.pointerInto()?.let(::sv)
                    add("insnCallsDelete", at, f.entryPoint, Term(freed ?: "invalid"))
                    thisCalls += ThisCall(at, f.entryPoint, callee?.entryPoint, freed, ThisCall.Kind.DELETE)
                }

                thisArg != null -> thisCalls += ThisCall(
                    at,
                    f.entryPoint,
                    callee?.entryPoint,
                    thisArg,
                    ThisCall.Kind.METHOD,
                )
            }
        }

        /** Where [callee] takes its [index]th argument: its own parameter's storage, else its convention's. */
        private fun argPosition(callee: Function, index: Int): Any? = callee.parameters.getOrNull(index)?.takeIf {
            !it.variableStorage.isUnassignedStorage
        }?.variableStorage?.firstVarnode ?: (callee.callingConvention ?: program.compilerSpec.defaultCallingConvention)
            .getStorageLocations(
                program,
                arrayOf<DataType>(VoidDataType.dataType) + Array(index + 1) { PointerDataType(dtm) },
                false,
                false,
            ).getOrNull(index + 1)?.firstVarnode?.let { at ->
                when {
                    at.isRegister -> program.getRegister(at)?.baseRegister?.name?.lowercase()?.let(::Term)
                    at.address.isStackAddress -> stackIndex(at.address.offset)
                    else -> null
                }
            }

        /** A call through a vtable slot: the slot read from a pointer read from an object, both at constant offsets. */
        private fun virtualCall(op: PcodeOp) {
            val slotLoad = op.getInput(0).def?.takeIf { it.opcode == PcodeOp.LOAD } ?: return
            val slotInto = slotLoad.getInput(1).pointerInto() ?: return
            val vptrLoad = slotInto.root.instances.firstNotNullOfOrNull { it.def?.takeIf { d -> d.opcode == PcodeOp.LOAD } }
                ?: return
            val obj = vptrLoad.getInput(1).pointerInto() ?: return
            val slotOffset = slotLoad.getInput(1).pointerInto()?.offset ?: slotInto.offset
            if (slotOffset < 0 || obj.offset < 0) return
            add("possibleVirtualFunctionCall", op.seqnum.target, f.entryPoint, Term(sv(obj)), obj.offset, slotOffset)
        }

        private fun store(op: PcodeOp) {
            val dest = op.getInput(1)
            val value = op.getInput(2)
            access(op, dest, value.size)
            val table = value.constantAddress()
                ?.takeIf { value.size == ptrSize && isPointerTable(it) } ?: return
            val p = dest.pointerInto()?.takeIf { it.offset >= 0 } ?: return
            stored += table
            add("possibleVFTableWrite", op.seqnum.target, f.entryPoint, Term(sv(p.root)), p.offset, Term(sv(p)), table)
        }

        /** `methodMemberAccess/4`: a load or store of [size] bytes at a constant offset into `this`. */
        private fun access(op: PcodeOp, pointer: Varnode, size: Int?) {
            val thisRoot = thisVar ?: return
            val p = pointer.pointerInto() ?: return
            if (p.root != thisRoot || p.offset < 0 || size == null) return
            add("methodMemberAccess", op.seqnum.target, f.entryPoint, p.offset, size)
        }
    }

    /**
     * `returnsSelf/1` for a method the decompiler gave no return value: Pharos tests what the return register
     * holds whatever the signature says, and an Itanium constructor, `void`, often leaves `this` there. So the
     * method is decompiled again as returning a pointer, in a transaction rolled back after.
     */
    private fun returnsSelfOnceTyped(f: Function, first: HighFunction) {
        if (f.hasCustomVariableStorage()) return
        DecompInterface().useWith(program) { decomp ->
            program.runTransaction("Decompile as returning a pointer") {
                if (f.signatureSource == SourceType.DEFAULT) {
                    HighFunctionDBUtil.commitParamsToDatabase(
                        first,
                        true,
                        HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT,
                        SourceType.ANALYSIS,
                    )
                }
                f.setReturnType(PointerDataType(dtm), f.signatureSource)
                decomp.decompileFunction(f, DECOMPILE_TIMEOUT_SECONDS, monitor).highFunction?.apply {
                    val thisVar = pcodeOps.asSequence().flatMap { it.inputs.asSequence() }
                        .firstOrNull { it.isInput && it.high != null && positionOf(it) == abi.thisParam }?.high
                        ?: return@runTransaction
                    val returns = pcodeOps.asSequence()
                        .filter { it.opcode == PcodeOp.RETURN && it.numInputs > 1 }
                        .map { it.getInput(1).pointerInto() }
                        .toList()
                    if (returns.isNotEmpty() && returns.all { it == PointerInto(thisVar, 0) }) {
                        add("returnsSelf", f.entryPoint)
                    }
                }
            }
        }
    }

    /** Where [vn] comes in, as the rules spell it: a register's name, or the stack argument's index. */
    private fun positionOf(vn: Varnode): Any? = when {
        vn.isRegister -> program.getRegister(vn)?.baseRegister?.name?.lowercase()?.let(::Term)
        vn.address.isStackAddress -> stackIndex(vn.address.offset)
        else -> null
    }

    private fun stackIndex(offset: Long): Long? = (offset - ptrSize).takeIf { it >= 0 && it % ptrSize == 0L }
        ?.div(ptrSize)

    /**
     * What [f] is called, to tell `operator new` and `delete` by: its name, any other label at it, and for an
     * import the name it is imported by, mangled, which the demangler renamed (`_ZdlPv` to `operator.delete`).
     */
    private fun namesOf(f: Function): Set<String> = buildSet {
        add(f.name)
        add(f.name.replace('.', ' '))
        f.externalLocation?.originalImportedName?.let(::add)
        f.externalLocation?.label?.let(::add)
        program.symbolTable.getSymbols(f.entryPoint).forEach { add(it.name) }
    }

    // --- across functions ----------------------------------------------------------------------------------

    /**
     * `noCallsBefore/1` and `noCallsAfter/1`, as Pharos orders a function's calls on one object: a method is
     * no constructor once some other method is called on the same `this` before its first call there, no
     * destructor once one is called after its last, a call to `operator new` or `delete` ending the search.
     * Here in address order within each caller, not along its control flow.
     */
    private fun orderFacts(methods: Set<Address>, calls: List<ThisCall>) {
        val notFirst = mutableSetOf<Address>()
        val notLast = mutableSetOf<Address>()
        for (onObject in calls.filter { it.thisPtr != null }.groupBy { it.caller to it.thisPtr }.values) {
            val ordered = onObject.sortedBy { it.at }
            ordered.forEachIndexed { i, c ->
                if (c.kind != ThisCall.Kind.METHOD || c.callee == null) return@forEachIndexed
                val before = ordered.subList(0, i).takeLastWhile { it.kind == ThisCall.Kind.METHOD }
                if (before.none { it.callee == c.callee } && before.isNotEmpty()) notFirst += c.callee
                val after = ordered.subList(i + 1, ordered.size).takeWhile { it.kind == ThisCall.Kind.METHOD }
                if (after.none { it.callee == c.callee } && after.isNotEmpty()) notLast += c.callee
            }
        }
        for (m in methods) {
            if (m !in notFirst) add("noCallsBefore", m)
            if (m !in notLast) add("noCallsAfter", m)
        }
    }

    /**
     * `initialMemory/2` for each slot of the table at [start], up to the first word that is not code. Its first
     * [MAX_NULL_SLOTS] may be null: an abstract Itanium class's table leaves its destructors' slots so.
     */
    private fun vftableEntries(start: Long) {
        val at = address(start) ?: return
        val slotEntries = Itanium.slotOffsets(ptrSize).map(at::add)
            .mapNotNull { pfn -> program.pointerAt(pfn)?.let { pfn to it } }
        var nulls = 0
        for ((pfn, target) in slotEntries.take(MAX_SLOTS)) {
            when {
                target.offset == 0L && nulls < MAX_NULL_SLOTS -> nulls++

                program.isSlotCode(pfn, target) || target in purecalls.map(::address).filterNotNull().toSet() -> {
                    if (!facts.add(OoFact.of("initialMemory", pfn, target))) return
                }

                else -> return
            }
        }
    }

    /** A table of pointers to code at [start] in data: what a vptr store's constant must point at. */
    private fun isPointerTable(start: Long): Boolean {
        val at = address(start) ?: return false
        val block = memory.getBlock(at) ?: return false
        return when {
            !block.isInitialized -> false
            block.isExecute && !block.isRead -> false
            block.isExecute && functions.getFunctionContaining(at) != null -> false
            else -> Itanium.slotOffsets(ptrSize).take(MAX_NULL_SLOTS + 1)
                .map(at::add).mapNotNull(program::pointerAt)
                .firstOrNull { it.offset != 0L }?.let { program.isSlotCode(at, it) } == true
        }
    }

    private fun isPureVirtual(f: Function) = PlainVtables.isPureVirtualStub(f.name) ||
        f.getThunkedFunction(true)?.name?.let(PlainVtables::isPureVirtualStub) == true

    // --- MSVC RTTI -----------------------------------------------------------------------------------------

    /**
     * The `rTTI*` facts of each Complete Object Locator: those the pointer before one of [vftables] points at,
     * and those Ghidra's RTTI analyzer laid. A 64-bit one's pointers are image-relative; written absolute.
     */
    private fun rtti(vftables: MutableSet<Long>) {
        val visited = mutableSetOf<Long>()
        for ((ptr, col) in locators(vftables).toSortedMap()) {
            if (locator(ptr, col, visited)) vftables += ptr + ptrSize
        }
    }

    /** Each pointer to a Complete Object Locator, to the locator. */
    private fun locators(vftables: Set<Long>) = buildMap {
        for (vft in vftables) {
            val ptr = address(vft - ptrSize) ?: continue
            readPointer(ptr)?.let { this[ptr.offset] = it }
        }
        for (data in program.listing.getDefinedData(true) as Iterable<Data>) {
            if (data.dataType.name != "RTTICompleteObjectLocator") continue
            for (ref in program.referenceManager.getReferencesTo(data.address)) {
                if (program.listing.getDataContaining(ref.fromAddress)?.isPointer == true) {
                    this[ref.fromAddress.offset] = data.address.offset
                }
            }
        }
    }

    /** The locator at [col], which [ptr] points at, and what it describes; whether it is one. */
    private fun locator(ptr: Long, col: Long, visited: MutableSet<Long>): Boolean {
        val at = address(col) ?: return false
        if (readInt(at) != if (ptrSize == 8) 1L else 0L) return false
        val offset = readInt(at.add(4)) ?: return false
        val cdOffset = readInt(at.add(8)) ?: return false
        val td = rva(at.add(12)) ?: return false
        val chd = rva(at.add(16)) ?: return false
        val name = typeName(td) ?: return false
        add("rTTICompleteObjectLocator", ptr, col, td, chd, offset, cdOffset)
        typeDescriptor(td, name, visited)
        hierarchy(chd, visited)
        return true
    }

    private fun address(offset: Long): Address? =
        runCatching { program.addressFactory.defaultAddressSpace.getAddress(offset) }.getOrNull()

    private fun rva(at: Address): Long? = readInt(at)?.plus(
        when (ptrSize) {
            8 -> program.imageBase.offset
            else -> 0
        },
    )

    private fun typeName(td: Long): String? = runCatching {
        val at = address(td + 2L * ptrSize) ?: return null
        val bytes = generateSequence(0L) { it + 1 }.take(MAX_NAME).map { memory.getByte(at.add(it)) }
            .takeWhile { it != 0.toByte() }.toList().toByteArray()
        String(bytes, Charsets.ISO_8859_1).takeIf { it.startsWith(".?A") }
    }.getOrNull()

    private fun typeDescriptor(td: Long, name: String, visited: MutableSet<Long>) {
        if (!visited.add(td)) return
        val at = address(td) ?: return
        add("rTTITypeDescriptor", td, readPointer(at) ?: 0L, name, demangledType(at, name))
    }

    /** The class [name] spells (`.?AVOuter@ns@@`: `ns::Outer`), the descriptor's namespace where Ghidra named it. */
    private fun demangledType(at: Address, name: String): String {
        val ns = program.symbolTable.getPrimarySymbol(at)?.parentNamespace
        if (ns != null && !ns.isGlobal) return ns.getName(true)
        return name.removePrefix(".?A").drop(1).removeSuffix("@@").split('@').reversed().joinToString("::")
    }

    private fun hierarchy(chd: Long, visited: MutableSet<Long>) {
        if (!visited.add(chd)) return
        val at = address(chd) ?: return
        val attributes = readInt(at.add(4)) ?: return
        val count = readInt(at.add(8))?.takeIf { it in 0..MAX_BASES } ?: return
        val array = rva(at.add(12)) ?: return
        val bases = (0 until count).mapNotNull { i -> address(array + 4 * i)?.let(::rva) }
        for (bcd in bases) {
            val b = address(bcd) ?: continue
            val td = rva(b) ?: continue
            val fields = (1..5).map { readInt(b.add(4L * it)) ?: return }
            val (contained, mdisp, pdisp, vdisp, attrs) = fields
            val sub = if (attrs and 0x40L != 0L) rva(b.add(24)) ?: 0L else 0L
            if (visited.add(bcd)) add("rTTIBaseClassDescriptor", bcd, td, contained, mdisp, pdisp, vdisp, attrs, sub)
            typeName(td)?.let { typeDescriptor(td, it, visited) }
            if (sub != 0L) hierarchy(sub, visited)
        }
        add("rTTIClassHierarchyDescriptor", chd, attributes, bases)
    }

    private companion object {
        const val MAX_SLOTS = 1024

        /** The null slots a table may start with: an abstract Itanium class's complete and deleting destructors. */
        const val MAX_NULL_SLOTS = 2
        const val MAX_NAME = 512
        const val MAX_BASES = 256L
        val ABIS = listOf(Itanium, Msvc, Gcc2Thunks)
        val OPERATOR_NEW = ABIS.flatMap { it.operatorNewNames }.toSet()
        val OPERATOR_DELETE = ABIS.flatMap { it.operatorDeleteNames }.toSet()
    }
}

/** The address [this] is, a constant or a global's address (`PTRSUB 0, addr`), through copies and casts. */
private fun Varnode.constantAddress(): Long? {
    val d = def ?: return if (isConstant) offset else null
    return when (d.opcode) {
        PcodeOp.COPY, PcodeOp.CAST -> d.getInput(0).constantAddress()
        PcodeOp.PTRSUB -> d.getInput(1).takeIf { it.isConstant }?.offset
            ?.takeIf { d.getInput(0).isConstant && d.getInput(0).offset == 0L }
        else -> if (isConstant) offset else null
    }
}
