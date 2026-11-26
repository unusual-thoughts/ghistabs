package ghicpp.ooa

import ghicpp.abi.generic.PlainVtables
import ghicpp.abi.holdsPureVirtualStub
import ghicpp.abi.msvc.Msvc
import ghicpp.dissect.CalledObject
import ghicpp.dissect.DECOMPILE_TIMEOUT_SECONDS
import ghicpp.dissect.ObjectCall
import ghicpp.dissect.PointerInto
import ghicpp.dissect.constantAddress
import ghicpp.dissect.decompileEach
import ghicpp.dissect.objectCalls
import ghicpp.dissect.offsetFrom
import ghicpp.dissect.pointerInto
import ghicpp.dissect.thisVariable
import ghicpp.hierarchy.slotTablesOf
import ghicpp.thisAt
import ghicpp.thisStorage
import ghidra.app.cmd.data.TypeDescriptorModel
import ghidra.app.cmd.data.rtti.Rtti3Model
import ghidra.app.cmd.data.rtti.Rtti4Model
import ghidra.app.decompiler.DecompInterface
import ghidra.app.decompiler.util.FillOutStructureHelper
import ghidra.app.util.datatype.microsoft.DataValidationOptions
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.VoidDataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.HighFunctionDBUtil
import ghidra.program.model.pcode.HighVariable
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghidrakt.orThunked
import ghidrakt.pointerAt
import ghidrakt.rolledBack
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
 * Writes OOAnalyzer's initial facts for a program that our analyzers already ran on, for its Prolog rules
 * (`ooprolog --facts`) to recover the classes from.
 *
 * What our analysis established is taken from it, not found again. The vftables are the ones our analyzers
 * labelled in their classes, with the slots they laid ([slotTablesOf]). The calls on each object are those
 * the dissector reads ([objectCalls]), with `this` where our method convention puts it ([thisAt]). The
 * accesses through `this` are those Ghidra's structure fill follows, as our class structs are filled. MSVC's
 * RTTI is read through Ghidra's RTTI models, as [ghicpp.abi.msvc.MsvcRttiParser] reads it. What only
 * OOAnalyzer asks for is read off the decompiler here: each function's parameters and calls, the virtual
 * calls, `operator new` and `delete`, and whether a method returns `this`.
 *
 * A symbolic value (`sv_…`) is a decompiled variable of one function, `sv_<function>_<n>`, or a constant
 * offset into one, `sv_<function>_<n>_<offset>`, with a `thisPtrOffset/3` between the two. The facts the
 * rules never read (`thisPtrDefinition`, `funcReturn`, `callReturn`) and those this has no analysis for
 * (`uninitializedReads`, `possibleVBTableWrite`, `symbolClass`) are left out.
 */
class OoFactExporter(private val program: Program, private val monitor: TaskMonitor = TaskMonitor.DUMMY) {
    val abi = OoAbi.of(program)
    private val ptrSize = abi.ptrSize
    private val dtm = program.dataTypeManager
    private val thisStorage = program.thisStorage()
    private val facts = linkedSetOf<OoFact>()

    private fun add(predicate: String, vararg args: Any) {
        facts += OoFact.of(predicate, *args)
    }

    /** Each vftable our analyzers labelled, by its address point, to where each of its slots is. */
    private val vftables: Map<Address, List<Address>> by lazy {
        program.symbolTable.classNamespaces.asSequence()
            .flatMap { program.slotTablesOf(it) }
            .associate { it.address to it.pfns }
    }

    /** Every fact, in the order they were found: functions by address, each one's in its p-code's order. */
    fun export(): List<OoFact> {
        facts.clear()
        add("fileInfo", program.executableMD5.orEmpty().uppercase(), program.name, Term(abi.name), ptrSize)
        val all = (program.functionManager.getFunctions(true) as Iterable<Function>).filter { !it.isExternal }
        for (f in all) {
            if (program.holdsPureVirtualStub(
                    f.entryPoint,
                    PlainVtables::isPureVirtualStub,
                )
            ) {
                add("purecall", f.entryPoint)
            }
            f.getThunkedFunction(false)?.takeIf { !it.isExternal }?.let { add("thunk", f.entryPoint, it.entryPoint) }
        }
        val methods = mutableSetOf<Address>()
        val calls = mutableListOf<List<ObjectCall>>()
        val decomp = DecompInterface()
        decomp.decompileEach(program, all.filter { !it.isThunk }, monitor, "Exporting OOAnalyzer facts") { f, high ->
            val read = FunctionFacts(f, high).apply { read() }
            if (read.thisVar != null) {
                methods += f.entryPoint
                if (!read.returnsValue) f.returnsSelfOnceTyped(high, decomp)
            }
            calls += high.objectCalls(f.thisAt(thisStorage))
        }
        orderFacts(methods, calls)
        for ((_, pfns) in vftables) {
            for (pfn in pfns) program.pointerAt(pfn)?.let { add("initialMemory", pfn, it) }
        }
        if (abi.isMsvc) rtti()
        return facts.toList()
    }

    fun write(out: Writer) {
        out.write("% Prolog facts for OOAnalyzer, exported by ghicpp from ${program.name}.\n")
        export().forEach { out.write("$it\n") }
        out.write("% Object fact exporting complete.\n")
    }

    // --- per function --------------------------------------------------------------------------------------

    private inner class FunctionFacts(val f: Function, val high: HighFunction) {
        private val ids = mutableMapOf<HighVariable, Int>()

        /** The variable `this` comes in as, where our method convention puts it ([thisAt]). */
        val thisVar: HighVariable? = high.thisVariable(f.thisAt(thisStorage))

        /** Whether the decompiler gave the function a return value at all, so that [read] could test it. */
        var returnsValue = false
            private set

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
            members()
            val returns = mutableListOf<Boolean>()
            for (op in high.pcodeOps.asSequence().sortedBy { it.seqnum }) {
                when (op.opcode) {
                    PcodeOp.CALL -> call(op)
                    PcodeOp.CALLIND -> virtualCall(op)
                    PcodeOp.STORE -> vftableWrite(op)
                    PcodeOp.RETURN -> if (op.numInputs > 1) returns += op.getInput(1).isThis()
                }
            }
            returnsValue = returns.isNotEmpty()
            if (returns.isNotEmpty() && returns.all { it }) add("returnsSelf", f.entryPoint)
        }

        private fun Varnode.isThis() = thisVar != null && pointerInto() == PointerInto(thisVar, 0L)

        /** `funcParameter/3` for each input the decompiler found it reading, and the conventions they allow. */
        private fun params() {
            val inputs = high.pcodeOps.asSequence().flatMap { it.inputs.asSequence() }
                .filter { it.isInput && it.high != null }.distinctBy { it.address to it.size }.toList()
            val positions = inputs.mapNotNull { vn -> positionOf(vn)?.let { it to vn } }
            for ((pos, vn) in positions) add("funcParameter", f.entryPoint, pos, Term(sv(vn.high)))
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

        /**
         * `methodMemberAccess/4` for each load and store through `this`, at a constant offset. These are the
         * accesses Ghidra's structure fill follows, the same ones our class structs are filled from.
         */
        private fun members() {
            val thisVar = thisVar ?: return
            val fill = FillOutStructureHelper(program, monitor)
            fill.processStructure(thisVar, f, true, false, null)
            val loads = fill.loadPcodeOps.map { it to it.pcodeOp.output?.size }
            val stores = fill.storePcodeOps.map { it to it.pcodeOp.getInput(2).size }
            for ((access, size) in (loads + stores).sortedBy { it.first.pcodeOp.seqnum }) {
                if (access.offset < 0 || size == null) continue
                add("methodMemberAccess", access.pcodeOp.seqnum.target, f.entryPoint, access.offset, size)
            }
        }

        private fun call(op: PcodeOp) {
            val at = op.seqnum.target
            val target = op.getInput(0).address
            add("callTarget", at, f.entryPoint, target)
            val callee = program.functionManager.getFunctionAt(target) ?: return
            val args = (1 until op.numInputs).map { op.getInput(it) }
            args.forEachIndexed { i, arg ->
                val pos = argPosition(callee, i) ?: return@forEachIndexed
                val p = arg.pointerInto() ?: return@forEachIndexed
                add("callParameter", at, f.entryPoint, pos, Term(sv(p)))
            }
            when (callee.orThunked.name) {
                in OPERATOR_NEW -> {
                    val out = op.output?.high?.let { sv(it) }
                    add("insnCallsNew", at, f.entryPoint, Term(out ?: "invalid"))
                    val size = args.firstOrNull()?.takeIf { it.isConstant }?.offset
                    if (out != null && size != null) {
                        add("thisPtrAllocation", at, f.entryPoint, Term(out), Term("type_Heap"), size)
                    }
                }

                in OPERATOR_DELETE -> {
                    val freed = args.firstOrNull()?.pointerInto()?.let(::sv)
                    add("insnCallsDelete", at, f.entryPoint, Term(freed ?: "invalid"))
                }
            }
        }

        /** Where [callee] takes its [index]th argument: its own parameter's storage, else its convention's. */
        private fun argPosition(callee: Function, index: Int): Any? = callee.parameters.getOrNull(index)
            ?.variableStorage?.takeIf { !it.isUnassignedStorage }?.firstVarnode?.let(::positionOf)
            ?: (callee.callingConvention ?: program.compilerSpec.defaultCallingConvention)
                .getStorageLocations(
                    program,
                    arrayOf<DataType>(VoidDataType.dataType) + Array(index + 1) { PointerDataType(dtm) },
                    false,
                    false,
                ).getOrNull(index + 1)?.firstVarnode?.let(::positionOf)

        /** A call through a vtable slot: the slot read from a pointer read from an object, both at constant offsets. */
        private fun virtualCall(op: PcodeOp) {
            val (slot, _) = op.getInput(0).offsetFrom()
            val slotLoad = slot.def?.takeIf { it.opcode == PcodeOp.LOAD } ?: return
            val (vptr, slotOffset) = slotLoad.getInput(1).offsetFrom()
            val vptrLoad = vptr.def?.takeIf { it.opcode == PcodeOp.LOAD } ?: return
            val obj = vptrLoad.getInput(1).pointerInto() ?: return
            if (slotOffset < 0 || obj.offset < 0) return
            add("possibleVirtualFunctionCall", op.seqnum.target, f.entryPoint, Term(sv(obj)), obj.offset, slotOffset)
        }

        /** `possibleVFTableWrite/6`: a store of one of the vftables our analyzers found into an object. */
        private fun vftableWrite(op: PcodeOp) {
            val table = op.getInput(2).constantAddress(program)?.takeIf { it in vftables } ?: return
            val p = op.getInput(1).pointerInto()?.takeIf { it.offset >= 0 } ?: return
            add("possibleVFTableWrite", op.seqnum.target, f.entryPoint, Term(sv(p.root)), p.offset, Term(sv(p)), table)
        }
    }

    /**
     * `returnsSelf/1` for a method the decompiler gave no return value. Pharos tests what the return register
     * holds whatever the signature says, and an Itanium constructor, `void`, often leaves `this` there. So the
     * method is decompiled again as returning a pointer, in a transaction that is rolled back after.
     */
    private fun Function.returnsSelfOnceTyped(first: HighFunction, decomp: DecompInterface) {
        if (hasCustomVariableStorage()) return
        program.rolledBack("Decompile as returning a pointer") {
            // The decompiler ignores the return type of a default signature, which is not locked. Locking the
            // parameters it found first keeps `this` where it was.
            if (signatureSource == SourceType.DEFAULT) {
                HighFunctionDBUtil.commitParamsToDatabase(
                    first,
                    true,
                    HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT,
                    SourceType.ANALYSIS,
                )
            }
            setReturnType(PointerDataType(dtm), signatureSource)
            val high = decomp.decompileFunction(this, DECOMPILE_TIMEOUT_SECONDS, monitor).highFunction
                ?: return@rolledBack
            val thisVar = high.thisVariable(thisAt(thisStorage)) ?: return@rolledBack
            val returned = high.pcodeOps.asSequence()
                .filter { it.opcode == PcodeOp.RETURN && it.numInputs > 1 }
                .map { it.getInput(1).pointerInto() }
                .toList()
            if (returned.isNotEmpty() && returned.all { it == PointerInto(thisVar, 0L) }) add("returnsSelf", entryPoint)
        }
    }

    /** Where [vn] comes in, as the rules spell it: a register's name, or the stack argument's index. */
    private fun positionOf(vn: Varnode): Any? = when {
        vn.isRegister -> program.getRegister(vn)?.baseRegister?.name?.lowercase()?.let(::Term)

        vn.address.isStackAddress -> (vn.address.offset - ptrSize).takeIf { it >= 0 && it % ptrSize == 0L }
            ?.div(ptrSize)

        else -> null
    }

    // --- across functions ----------------------------------------------------------------------------------

    /**
     * `noCallsBefore/1` and `noCallsAfter/1`, as Pharos orders a function's calls on one object. A method is no
     * constructor once another method is called on the same object before its first call there. It is no
     * destructor once another is called after its last. A call of `operator delete` ends the search. The calls
     * on each object are the ones the dissector reads ([objectCalls]), in address order within each caller,
     * not along its control flow.
     */
    private fun orderFacts(methods: Set<Address>, calls: List<List<ObjectCall>>) {
        val notFirst = mutableSetOf<Address>()
        val notLast = mutableSetOf<Address>()
        fun ObjectCall.frees() = callee.name in OPERATOR_DELETE
        for (onObject in calls.flatMap { inCaller -> inCaller.groupBy { it.obj to it.offset }.values }) {
            val ordered = onObject.sortedBy { it.at }
            ordered.forEachIndexed { i, c ->
                if (c.frees()) return@forEachIndexed
                val before = ordered.subList(0, i).takeLastWhile { !it.frees() }
                if (before.isNotEmpty() && before.none { it.callee == c.callee }) notFirst += c.callee.entryPoint
                val after = ordered.subList(i + 1, ordered.size).takeWhile { !it.frees() }
                if (after.isNotEmpty() && after.none { it.callee == c.callee }) notLast += c.callee.entryPoint
            }
        }
        for (m in methods) {
            if (m !in notFirst) add("noCallsBefore", m)
            if (m !in notLast) add("noCallsAfter", m)
        }
    }

    // --- MSVC RTTI -----------------------------------------------------------------------------------------

    private val options = DataValidationOptions()

    private fun labelled(name: String) =
        program.symbolTable.getSymbols(name).iterator().asSequence().map { it.address }.distinct()

    /**
     * The `rTTI*` facts, read through Ghidra's RTTI models off the labels its RTTI analyzer laid. These are the
     * Complete Object Locator each vftable's meta pointer points at, and every Class Hierarchy Descriptor. A
     * 64-bit locator's pointers are image-relative, and the models give them as absolute addresses.
     */
    private fun rtti() {
        val seen = mutableSetOf<Address>()
        for (meta in labelled(Msvc.VFTABLE_META_PTR)) {
            val col = program.pointerAt(meta) ?: continue
            runCatching {
                val locator = Rtti4Model(program, col, options)
                add(
                    "rTTICompleteObjectLocator",
                    meta,
                    col,
                    locator.rtti0Address,
                    locator.rtti3Address,
                    u32(locator.vbTableOffset),
                    u32(locator.constructorOffset),
                )
                typeDescriptor(locator.rtti0Model, seen)
                hierarchy(locator.rtti3Model, seen)
            }
        }
        for (chd in labelled(Msvc.CLASS_HIERARCHY_DESCRIPTOR)) {
            runCatching { hierarchy(Rtti3Model(program, chd, options), seen) }
        }
    }

    private fun typeDescriptor(td: TypeDescriptorModel, seen: MutableSet<Address>) {
        if (!seen.add(td.address)) return
        val vftable = runCatching { td.vfTableAddress }.getOrNull() ?: 0L
        val name = td.typeName ?: return
        add("rTTITypeDescriptor", td.address, vftable, name, demangledType(td.address, name))
    }

    /**
     * The class [name] spells (`.?AVOuter@ns@@`: `ns::Outer`): the namespace of the descriptor's label, where
     * Ghidra put it in one, else the name itself, unmangled.
     */
    private fun demangledType(at: Address, name: String): String {
        val ns = program.symbolTable.getPrimarySymbol(at)?.parentNamespace
        if (ns != null && !ns.isGlobal) return ns.getName(true)
        return name.removePrefix(".?A").drop(1).removeSuffix("@@").split('@').reversed().joinToString("::")
    }

    /** The descriptor [chd], each Base Class Descriptor in its array, and the classes those describe. */
    private fun hierarchy(chd: Rtti3Model, seen: MutableSet<Address>) {
        if (!seen.add(chd.address)) return
        val array = chd.rtti2Model
        val bases = (0 until chd.rtti1Count).map { array.getRtti1Address(it) }
        for (i in bases.indices) {
            val bcd = array.getRtti1Model(i)
            val nested = bcd.rtti3Address.takeIf { bcd.attributes and BCD_HAS_HIERARCHY != 0 }
            if (seen.add(bcd.address)) {
                add(
                    "rTTIBaseClassDescriptor",
                    bcd.address,
                    bcd.rtti0Address,
                    u32(bcd.numBases),
                    u32(bcd.mDisp),
                    u32(bcd.pDisp),
                    u32(bcd.vDisp),
                    u32(bcd.attributes),
                    nested ?: 0L,
                )
            }
            typeDescriptor(bcd.rtti0Model, seen)
            nested?.let { runCatching { hierarchy(bcd.rtti3Model, seen) } }
        }
        add("rTTIClassHierarchyDescriptor", chd.address, u32(chd.attributes), bases)
    }

    /** [value] as the unsigned 32-bit word memory holds, which is how OOAnalyzer's facts write RTTI fields. */
    private fun u32(value: Int) = value.toLong() and 0xffffffffL

    private companion object {
        val OPERATOR_NEW = PlainVtables.operatorNewNames
        val OPERATOR_DELETE = PlainVtables.operatorDeleteNames

        /** A Base Class Descriptor's attribute: it points at the Class Hierarchy Descriptor of its class. */
        const val BCD_HAS_HIERARCHY = 0x40
    }
}
