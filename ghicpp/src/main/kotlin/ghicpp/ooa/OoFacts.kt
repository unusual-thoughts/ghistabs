package ghicpp.ooa

import ghicpp.abi.gcc2.Gcc2Thunks
import ghicpp.abi.generic.PlainVtables
import ghicpp.abi.itanium.Itanium
import ghicpp.abi.msvc.Msvc
import ghicpp.dissect.CalledObject
import ghicpp.dissect.DECOMPILE_TIMEOUT_SECONDS
import ghicpp.dissect.PointerInto
import ghicpp.dissect.decompileEach
import ghicpp.dissect.pointerInto
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

    val thisParam: Any get() = when (this) {
        MSVC_32 -> Term("ecx")
        MSVC_64 -> Term("rcx")
        SYSV_32 -> 0L
        SYSV_64 -> Term("rdi")
    }

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

/** Writes OOAnalyzer's initial Prolog facts from Ghidra's listing and decompiler. */
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

    private var purecalls: Set<Long> = emptySet()

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
            val thisAt = f.argumentAt(0)
            val objectCalls = high.objectCalls(thisAt)
            val stores = objectCalls.filter { it.obj == CalledObject.This && !it.slot }
            val FunctionFacts(f, high).run {
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

    class ThisCall(val at: Address, val caller: Address, val callee: Address?, val thisPtr: String?, val kind: Kind) {
        enum class Kind { METHOD, NEW, DELETE }
    }

    private inner class FunctionFacts(val f: Function, val high: HighFunction) {
        private val ids = mutableMapOf<HighVariable, Int>()
        val stored = mutableSetOf<Long>()
        val thisCalls = mutableListOf<ThisCall>()
        var thisVar: HighVariable? = null

        private fun sv(root: HighVariable, offset: Long = 0): String {
            val n = ids.getOrPut(root) { ids.size }
            val base = "sv_${f.entryPoint.offset.toString(16)}_$n"
            if (offset == 0L) return base
            val suffix = if (offset < 0) "m" + (-offset).toString(16) else offset.toString(16)
            val derived = "${base}_$suffix"
            add("thisPtrOffset", Term(base), offset, Term(derived))
            return derived
        }

        private fun sv(p: PointerInto) = sv(p.root, p.offset)

        fun read() {
            params()
            val returns = mutableListOf<Boolean>()
            for (op in high.pcodeOps.asSequence().sortedBy { it.seqnum }) {
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

        var returnsValue = false

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
                else -> listOf(abi.thisCall).filter { thisVar != null || read.isEmpty() }
            }
            conventions.forEach { add("callingConvention", f.entryPoint, it) }
        }

        private fun call(op: PcodeOp) {
            val at = op.seqnum.target
            val callee = high.directCallee(op) ?: return
            add("callTarget", at, f.entryPoint, op.getInput(0).address)
            val args = (1 until op.numInputs).map { op.getInput(it) }
            var thisArg: String? = null
            args.forEachIndexed { i, arg ->
                val pos = argPosition(callee, i) ?: return@forEachIndexed
                val p = arg.pointerInto() ?: return@forEachIndexed
                val term = sv(p)
                add("callParameter", at, f.entryPoint, pos, Term(term))
                if (pos == abi.thisParam) thisArg = term
            }
            val names = namesOf(callee)
            when {
                names.any { it in OPERATOR_NEW } -> {
                    val out = op.output?.high?.let { sv(it) }
                    add("insnCallsNew", at, f.entryPoint, Term(out ?: "invalid"))
                    val size = args.firstOrNull()?.takeIf { it.isConstant }?.offset
                    if (out != null && size != null) add(
                        "thisPtrAllocation",
                        at,
                        f.entryPoint,
                        Term(out),
                        Term("type_Heap"),
                        size,
                    )
                    thisCalls += ThisCall(at, f.entryPoint, callee.entryPoint, out, ThisCall.Kind.NEW)
                }
                names.any { it in OPERATOR_DELETE } -> {
                    val freed = args.firstOrNull()?.pointerInto()?.let(::sv)
                    add("insnCallsDelete", at, f.entryPoint, Term(freed ?: "invalid"))
                    thisCalls += ThisCall(at, f.entryPoint, callee.entryPoint, freed, ThisCall.Kind.DELETE)
                }
                thisArg != null -> thisCalls +=
                    ThisCall(at, f.entryPoint, callee.entryPoint, thisArg, ThisCall.Kind.METHOD)
            }
        }

        private fun argPosition(callee: Function, index: Int): Any? =
            callee.parameters.getOrNull(index)?.takeIf { !it.variableStorage.isUnassignedStorage }
                ?.variableStorage?.firstVarnode
                ?: (callee.callingConvention ?: program.compilerSpec.defaultCallingConvention)
                    .getStorageLocations(
                        program,
                        arrayOf<DataType>(VoidDataType.dataType) + Array(index + 1) { PointerDataType(dtm) },
                        false,
                        false,
                    ).getOrNull(index + 1)?.firstVarnode?.let(::positionOf)

        private fun virtualCall(op: PcodeOp) {
            val slotLoad = op.getInput(0).def?.takeIf { it.opcode == PcodeOp.LOAD } ?: return
            val slotPointer = slotLoad.getInput(1).pointerInto() ?: return
            val objPointer = slotPointer.root.instances.firstNotNullOfOrNull { v ->
                v.def?.takeIf { it.opcode == PcodeOp.LOAD }?.getInput(1)?.pointerInto()
            } ?: return
            val slotOffset = slotPointer.offset
            if (slotOffset < 0 || objPointer.offset < 0) return
            add("possibleVirtualFunctionCall", op.seqnum.target, f.entryPoint, Term(sv(objPointer)), objPointer.offset, slotOffset)
        }

        private fun store(op: PcodeOp) {
            val dest = op.getInput(1)
            val value = op.getInput(2)
            access(op, dest, value.size)
            val table = value.constantAddress()?.takeIf { value.size == ptrSize && isPointerTable(it) } ?: return
            val p = dest.pointerInto()?.takeIf { it.offset >= 0 } ?: return
            stored += table
            add("possibleVFTableWrite", op.seqnum.target, f.entryPoint, Term(sv(p.root)), p.offset, Term(sv(p)), table)
        }

        private fun access(op: PcodeOp, pointer: Varnode, size: Int?) {
            val p = pointer.pointerInto() ?: return
            if (p.root != thisVar || p.offset < 0 || size == null) return
            add("methodMemberAccess", op.seqnum.target, f.entryPoint, p.offset, size)
        }
    }

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

    private fun positionOf(vn: Varnode): Any? = when {
        vn.isRegister -> program.getRegister(vn)?.baseRegister?.name?.lowercase()?.let(::Term)
        vn.address.isStackAddress -> stackIndex(vn.address.offset)
        else -> null
    }

    private fun stackIndex(offset: Long): Long? = (offset - ptrSize).takeIf { it >= 0 && it % ptrSize == 0L }?.div(ptrSize)

    private fun namesOf(f: Function): Set<String> = buildSet {
        add(f.name)
        add(f.name.replace('.', ' '))
        f.externalLocation?.originalImportedName?.let(::add)
        f.externalLocation?.label?.let(::add)
        program.symbolTable.getSymbols(f.entryPoint).forEach { add(it.name) }
    }

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

    private fun vftableEntries(start: Long) {
        val at = address(start) ?: return
        val slots = program.functionSlots(at, Itanium) { f -> Itanium.isPureVirtualStub(f.name) }
        for (target in slots.take(MAX_SLOTS)) {
            val pfn = at
            facts += OoFact.of("initialMemory", pfn, target)
        }
    }

    private fun isPointerTable(start: Long): Boolean {
        val at = address(start) ?: return false
        val block = memory.getBlock(at) ?: return false
        if (!block.isInitialized || (block.isExecute && !block.isRead)) return false
        if (block.isExecute && functions.getFunctionContaining(at) != null) return false
        return program.functionSlots(at, Itanium) { f -> Itanium.isPureVirtualStub(f.name) }.take(1).any()
    }

    private fun isPureVirtual(f: Function) = PlainVtables.isPureVirtualStub(f.name) ||
        f.getThunkedFunction(true)?.name?.let(PlainVtables::isPureVirtualStub) == true

    private fun rtti(vftables: MutableSet<Long>) {
        val visited = mutableSetOf<Long>()
        for ((ptr, col) in locators(vftables).toSortedMap()) {
            if (locator(ptr, col, visited)) vftables += ptr + ptrSize
        }
    }

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

    private fun rva(at: Address): Long? = readInt(at)?.plus(if (ptrSize == 8) program.imageBase.offset else 0)

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

    private fun readPointer(at: Address): Long? = program.pointerAt(at)?.offset

    private fun readInt(at: Address): Long? = runCatching { memory.getInt(at).toLong() and 0xffffffffL }.getOrNull()

    private companion object {
        const val MAX_SLOTS = 1024
        const val MAX_NAME = 512
        const val MAX_BASES = 256L
        val ABIS = listOf(Itanium, Msvc, Gcc2Thunks)
        val OPERATOR_NEW = ABIS.flatMap { it.operatorNewNames }.toSet()
        val OPERATOR_DELETE = ABIS.flatMap { it.operatorDeleteNames }.toSet()
    }
}

private fun Varnode.constantAddress(): Long? {
    val d = def ?: return if (isConstant) offset else null
    return when (d.opcode) {
        PcodeOp.COPY, PcodeOp.CAST -> d.getInput(0).constantAddress()
        PcodeOp.PTRSUB -> d.getInput(1).takeIf { it.isConstant }?.offset
            ?.takeIf { d.getInput(0).isConstant && d.getInput(0).offset == 0L }
        else -> if (isConstant) offset else null
    }
}
