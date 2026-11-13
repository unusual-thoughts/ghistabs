package ghicpp.recover

import ghicpp.ClassNaming
import ghicpp.abi.*
import ghicpp.abi.generic.PlainVtableParser
import ghicpp.abi.generic.PlainVtables
import ghicpp.describeVxTable
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRangeImpl
import ghidra.program.model.data.Array
import ghidra.program.model.data.Composite
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Reference
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghidra.util.task.TaskMonitor
import ghidrakt.*
import ghidrakt.diagnose.DiagnosticSink
import ghidrakt.diagnose.DummySink

/** The word at [src] holding [dst], and where code refers to it ([refs]). */
data class Pointer(val src: Address, val dst: Address, val refs: List<Address>)

/**
 * A table of pointers to functions at [addr]: the functions its [slots] point at, a null slot's at 0, and where
 * code refers to its first word ([refs]), as a constructor or destructor does to store it in its object.
 */
data class PotentialVtable(val addr: Address, val slots: List<Address>, val refs: List<Address>) {
    constructor(pointers: List<Pointer>) : this(
        pointers.first().src,
        pointers.map { (_, dst) -> dst },
        pointers.first().refs,
    )
    val range get() = AddressRangeImpl(addr, (slots.size * addr.pointerSize).toLong())
}

/**
 * Finds the vtables of a program whose RTTI no class pass reads, absent or in a format none knows, by their
 * shape alone ([potentialVtables]), and [seed]s each as the `vftable` of a class of its own, laid as a
 * `<Class>_vftable` typed off its slots, so the class pass ([ClassPass] over a [PlainVtableParser]) takes it
 * from there: the slots' targets made functions and moved into the class, its constructors and destructors
 * found by their stores of it.
 *
 * It reads references, so it finds most once most of the program is disassembled and its operand references
 * marked, and each run can find more, through the code the last made of slots, and cut a table it seeded where
 * code now refers to the middle of it.
 */
class GenericVftableFinder(
    private val program: Program,
    private val registry: DtmRegistry = DtmRegistry(program.dataTypeManager),
    sink: DiagnosticSink = DummySink,
) : DiagnosticSink by sink {
    val ptr = program.defaultPointerSize.toLong()
    private val listing = program.listing
    private val symtab = program.symbolTable
    private val builder = VftableBuilder(registry, program, sink)

    /**
     * Every run of words pointing at functions ([isSlot]) that no ABI's labels claim ([isClaimed]), whose
     * first word code takes the address of ([codeReferences]). A run ends before the next such word, which begins
     * another, at a symbol, at data laid other than one word ([isFree]), or past [DESTRUCTOR_SLOTS] nulls;
     * the nulls that end it are no slots. A table whose constructor isn't disassembled yet waits for a later run.
     */
    val potentialVtables: List<PotentialVtable> by lazy {
        program.findPointers()
            .filter { (src, dst) -> isFree(src) && (dst.offset == 0L || isSlot(src, dst)) }
            .map { (src, dst) -> pointerOf(src, dst) }
            .asIterable()
            .chunkWith { a, b -> b.src == a.src + ptr && !b.begins() && !isNamed(b.src) }
            .flatMap { it.splitAtNulls() }
            .filter { run -> run.first().begins() && !isClaimed(run.first().src) && run.any { it.dst.offset != 0L } }
            .map { PotentialVtable(it) }
    }

    private fun Pointer.begins() = refs.isNotEmpty()

    private fun pointerOf(src: Address, dst: Address) = Pointer(src, dst, codeReferences(src))

    /** [this] split past [DESTRUCTOR_SLOTS] nulls in a row, each part without the nulls that end it. */
    private fun List<Pointer>.splitAtNulls(): List<List<Pointer>> {
        val parts = mutableListOf(mutableListOf<Pointer>())
        var nulls = 0
        for (p in this) {
            nulls = if (p.dst.offset == 0L) nulls + 1 else 0
            when {
                nulls > DESTRUCTOR_SLOTS -> if (parts.last().isNotEmpty()) parts.add(mutableListOf())
                else -> parts.last() += p
            }
        }
        return parts.map { part -> part.dropLastWhile { it.dst.offset == 0L } }.filter { it.isNotEmpty() }
    }

    /**
     * Seeds each of [potentialVtables] as its own class's `vftable`, and returns how many it seeded. A table it
     * seeded before, which code now refers into, is cut short there and the rest seeded on its own. The class is
     * named after where its table is, `Klass_<address>`, since nothing else names it.
     */
    fun seed(monitor: TaskMonitor = TaskMonitor.DUMMY): Int {
        monitor.message = "Finding pointer tables"
        monitor.initialize(potentialVtables.size.toLong(), "Seeding vftables from pointer tables")
        var seeded = 0
        for (table in potentialVtables) {
            monitor.increment()
            val laid = listing.getDefinedDataContaining(table.addr)?.takeIf(::isSeeded)
            when {
                laid == null -> {}

                laid.address == table.addr -> {
                    if (laid.numComponents > table.slots.size) relay(laid, table.slots.size)
                    continue
                }

                else -> relay(laid, (table.addr.subtract(laid.address) / ptr).toInt())
            }
            val ns = symtab.buildClassNamespaces(listOf("$SEEDED_CLASS_PREFIX${table.addr}"), SEEDED)
            symtab.createLabel(table.addr, ClassNaming.VFTABLE, ns, SEEDED)
            lay(table, ns)
            seeded++
            debug("vftable-seeded", "${table.slots.size} slot(s), referred to from ${table.refs}", table.addr)
        }
        return seeded
    }

    /** Lays a `<Class>_vftable` at [table], typed off its slots, unless one was typed already. */
    private fun lay(table: PotentialVtable, ns: GhidraClass) {
        val path = ClassNaming.vftablePath(ns)
        val vftable = registry.getOrRegister<Structure>(path) {
            StructureDataType(path.categoryPath, path.dataTypeName, 0, program.dataTypeManager)
        }
        if (vftable.numComponents == 0) {
            builder.addSlots(vftable, path.categoryPath, table.slots, PlainVtables)
            vftable.describeVxTable(ns.name, ClassNaming.VFTABLE, PlainVtables.primaryVptrOffset)
        }
        program.forceCreateData(table.addr, vftable)
    }

    /** Lays the seeded table [laid] again with its first [slots] slots only. */
    private fun relay(laid: Data, slots: Int) {
        val vftable = laid.dataType as Structure
        listing.clearCodeUnits(laid.address, laid.maxAddress, false)
        while (vftable.numComponents > slots) vftable.delete(vftable.numComponents - 1)
        program.forceCreateData(laid.address, vftable)
        debug("vftable-cut", "$slots slot(s) left", laid.address)
    }

    /**
     * Where instructions take [at]'s address, or a pointer to it in code holds it, a literal pool's: not where they
     * jump or call there, nor read or write the word, as code does a GOT's or an import table's.
     */
    private fun codeReferences(at: Address): List<Address> =
        program.referenceManager.getReferencesTo(at).iterator().asSequence()
            .filterNot { it.referenceType.let { t -> t.isFlow || t.isRead || t.isWrite } }
            .filter { it.isFromInstruction() || it.isFromCodePointer() }
            .map { it.fromAddress }
            .toList()

    private fun Reference.isFromInstruction() = listing.getInstructionAt(fromAddress) != null

    private fun Reference.isFromCodePointer() =
        program.isCode(fromAddress) && listing.getDataAt(fromAddress)?.isPointer == true

    /** Whether a vtable label or symbol of any ABI's is at [at], other than one this finder seeded. */
    private fun isClaimed(at: Address) = symtab.getSymbols(at).any {
        (ClassNaming.isVftableLabel(it.name) && !isSeededLabel(it)) ||
            it.name == ClassNaming.VTABLE ||
            CxxAbi.ofVtableSymbol(it.name) != null
    }

    /**
     * Whether the word at [at] may be laid as a slot: nothing is laid there, or a word that is no struct or array,
     * or a table this finder seeded, which a later run may cut.
     */
    private fun isFree(at: Address): Boolean {
        val laid = listing.getDefinedDataContaining(at) ?: return true
        if (isSeeded(laid)) return true
        val dt = laid.baseDataType
        return laid.address == at && laid.length.toLong() == ptr && dt !is Composite && dt !is Array
    }

    /** Whether [laid] is a `<Class>_vftable` this finder laid, under its `vftable` label. */
    private fun isSeeded(laid: Data) =
        laid.dataType is Structure && symtab.getSymbols(laid.address).any(::isSeededLabel)

    private fun isSeededLabel(sym: Symbol) = sym.name == ClassNaming.VFTABLE && sym.source == SEEDED &&
        sym.parentNamespace.name.startsWith(SEEDED_CLASS_PREFIX)

    private fun isNamed(at: Address) = symtab.getPrimarySymbol(at)?.let {
        it.source != SourceType.DEFAULT && !isSeededLabel(it)
    } == true

    /**
     * Whether the word at [pfn] can be a slot pointing at [target]: an imported function's thunk, or code where
     * a function begins or could, at an instruction's start or undisassembled; not inside a function, where a
     * switch's jump table points.
     */
    private fun isSlot(pfn: Address, target: Address): Boolean {
        if (program.importedFunction(pfn, target) != null) return true
        if (!program.isCode(target) || !program.isInitialized(target)) return false
        if (listing.getDefinedDataContaining(target) != null) return false
        if (listing.getInstructionContaining(target)?.let { it.address != target } == true) return false
        return program.functionManager.getFunctionContaining(target)?.let { it.entryPoint == target } ?: true
    }

    companion object {
        /** A seeded table's label and class source, an analysis', so a stabs import's or a user's names win. */
        val SEEDED = SourceType.ANALYSIS

        const val SEEDED_CLASS_PREFIX = "Klass_"
    }
}
