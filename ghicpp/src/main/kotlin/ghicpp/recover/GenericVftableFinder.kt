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

    /** A secondary table of the group [primary] opens, for the base subobject at [offset] in the object. */
    data class Secondary(val primary: PotentialVtable, val offset: Long)

    /**
     * Each of [potentialVtables] that is an Itanium secondary vtable, by its address. An Itanium vtable group lays
     * a class's primary table and then one per base subobject not at offset 0, back to back, each after an
     * `offset_to_top` word and an rtti word (0 with no RTTI): 0 before the primary, `-k` before the table of the
     * subobject at `k`, and before either the vbase and vcall offsets of the subobject's virtual bases. So a
     * table whose `offset_to_top` is `-k` and that follows its group's tables with nothing between them but such
     * offsets is the secondary at `k` of the nearest table before it whose `offset_to_top` is 0.
     */
    val secondaries: Map<Address, Secondary> by lazy {
        buildMap {
            var primary: PotentialVtable? = null
            var end: Address? = null
            for (table in potentialVtables.sortedBy { it.addr }) {
                val top = table.addr.wordBefore(2)
                val rtti = table.addr.wordBefore(1)
                val contiguous = end != null && onlyOffsetsBetween(end, table.addr.subtractNoWrap(2 * ptr))
                when {
                    top == null || rtti == null || !isRttiWord(rtti) -> primary = null

                    top == 0L -> primary = table

                    top < 0 && -top < MAX_SUBOBJECT_OFFSET && -top % 4 == 0L && contiguous && primary != null ->
                        put(table.addr, Secondary(primary, -top))

                    else -> primary = null
                }
                end = table.range.maxAddress.next()
            }
        }
    }

    private fun Address.wordBefore(words: Int) = signedWordBefore(program, words)

    /** An rtti word: 0, with no RTTI, or a pointer to data, a typeinfo. */
    private fun isRttiWord(word: Long) = word == 0L || runCatching {
        program.memory.getBlock(program.addressFactory.defaultAddressSpace.getAddress(word))
            ?.let { it.isInitialized && !it.isExecute }
    }.getOrNull() == true

    /**
     * Whether the words from [from] up to [until] are a few vbase, vcall and top offsets and rtti words, as a group
     * holds between tables: the header of a secondary with no slots of its own, a virtual base's, is all it has.
     */
    private fun onlyOffsetsBetween(from: Address, until: Address): Boolean {
        if (until < from) return false
        val words = until.subtract(from) / ptr
        return words <= MAX_OFFSET_WORDS && (0 until words).all { i ->
            until.wordBefore((words - i).toInt())?.let {
                kotlin.math.abs(it) < MAX_SUBOBJECT_OFFSET || isRttiWord(it)
            } ==
                true
        }
    }

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
        val classOf = mutableMapOf<Address, GhidraClass>()
        for (table in potentialVtables.sortedBy { it.addr }) {
            monitor.increment()
            val laid = listing.getDefinedDataContaining(table.addr)?.takeIf(::isSeeded)
            when {
                laid == null -> {}

                laid.address == table.addr -> {
                    if (laid.numComponents > table.slots.size) relay(laid, table.slots.size)
                    symtab.getSymbols(table.addr).firstOrNull { it.name == ClassNaming.VFTABLE && isSeededLabel(it) }
                        ?.let { classOf[table.addr] = it.parentNamespace as GhidraClass }
                    continue
                }

                else -> relay(laid, (table.addr.subtract(laid.address) / ptr).toInt())
            }
            val secondary = secondaries[table.addr]?.takeIf { it.primary.addr in classOf }
            if (secondary != null) {
                val ns = classOf.getValue(secondary.primary.addr)
                val label = ClassNaming.plainSecondaryLabel(secondary.offset)
                symtab.createLabel(table.addr, label, ns, SEEDED)
                lay(table, ns, "${ns.name}_$label")
                debug("vftable-seeded-secondary", "of ${ns.name}, at +${secondary.offset}", table.addr)
            } else {
                val ns = symtab.buildClassNamespaces(listOf("$SEEDED_CLASS_PREFIX${table.addr}"), SEEDED)
                symtab.createLabel(table.addr, ClassNaming.VFTABLE, ns, SEEDED)
                classOf[table.addr] = ns
                lay(table, ns)
                debug("vftable-seeded", "${table.slots.size} slot(s), referred to from ${table.refs}", table.addr)
            }
            seeded++
        }
        return seeded
    }

    /** Lays a `<Class>_vftable` at [table], typed off its slots, unless one was typed already. */
    private fun lay(table: PotentialVtable, ns: GhidraClass, name: String? = null) {
        val path = name?.let { ClassNaming.vftableCategory(ns).at(it) } ?: ClassNaming.vftablePath(ns)
        val vftable = registry.getOrRegister<Structure>(path) {
            StructureDataType(path.categoryPath, path.dataTypeName, 0, program.dataTypeManager)
        }
        if (vftable.numComponents == 0) {
            builder.addSlots(vftable, path.categoryPath, table.slots, PlainVtables)
            val label = name?.removePrefix("${ns.name}_") ?: ClassNaming.VFTABLE
            vftable.describeVxTable(
                ns.name,
                label,
                ClassNaming.plainSubobjectOffset(label) ?: PlainVtables.primaryVptrOffset,
            )
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

    private fun isSeededLabel(sym: Symbol) = ClassNaming.isClassVftableLabel(sym.name) && sym.source == SEEDED &&
        sym.parentNamespace.name.startsWith(SEEDED_CLASS_PREFIX)

    private fun isNamed(at: Address) = symtab.getPrimarySymbol(at)?.let {
        it.source != SourceType.DEFAULT && !isSeededLabel(it)
    } == true

    /**
     * Whether the word at [pfn] can be a slot pointing at [target]: an imported function's thunk, or code
     * ([isSlotCode], so not back into a read-only block its table shares with the code) where a function begins
     * or could, at an instruction's start or undisassembled; not inside a function, where a switch's jump table
     * points.
     */
    private fun isSlot(pfn: Address, target: Address): Boolean {
        if (program.importedFunction(pfn, target) != null) return true
        if (!program.isSlotCode(pfn, target) || !program.isInitialized(target)) return false
        if (listing.getDefinedDataContaining(target) != null) return false
        if (listing.getInstructionContaining(target)?.let { it.address != target } == true) return false
        return program.functionManager.getFunctionContaining(target)?.let { it.entryPoint == target } ?: true
    }

    companion object {
        /** A seeded table's label and class source, an analysis', so a stabs import's or a user's names win. */
        val SEEDED = SourceType.ANALYSIS

        const val SEEDED_CLASS_PREFIX = "Klass_"

        /** How far into its object a base subobject may sit, for the words before a table to read as its offset. */
        const val MAX_SUBOBJECT_OFFSET = 0x10000L

        /** How many vbase and vcall offset words may sit between two tables of one group. */
        const val MAX_OFFSET_WORDS = 8L
    }
}
