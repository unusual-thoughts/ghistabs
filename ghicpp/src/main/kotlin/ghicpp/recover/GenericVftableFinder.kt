package ghicpp.recover

import ghicpp.ClassNaming
import ghicpp.CxxAbi
import ghicpp.abi.*
import ghicpp.abi.generic.*
import ghicpp.abi.generic.PlainVtables.MAX_SUBOBJECT_OFFSET
import ghicpp.describeVxTable
import ghicpp.fixup.isTailJumpTarget
import ghicpp.fixup.splitOffTailJumpTarget
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
import kotlin.math.abs

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
     * A run whose first slot is null also needs a vtable header in front of it ([hasVtableHeader]). An abstract
     * Itanium class leaves its destructor slots null, but MSVC fills a pure virtual's slot with `_purecall`.
     * Without the header, a null followed by code pointers is some other table, such as a CRT exception scope table.
     */
    val potentialVtables: List<PotentialVtable> by lazy {
        program.findPointers()
            .filter { (src, dst) -> isFree(src) && (dst.offset == 0L || isSlot(src, dst)) }
            .map { (src, dst) -> pointerOf(src, dst) }
            .asIterable()
            .chunkWith { a, b -> b.src == a.src + ptr && !b.begins() && !isNamed(b.src) }
            .flatMap { it.splitAtNulls() }
            .filter { run -> run.first().begins() && !isClaimed(run.first().src) && run.any { it.dst.offset != 0L } }
            .filter { run -> run.first().dst.offset != 0L || program.hasVtableHeader(run.first().src) }
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
                val header = program.vtableHeader(table.addr)
                val top = header?.offsetToTop
                val contiguous = end != null && onlyOffsetsBetween(end, table.addr.subtractNoWrap(2 * ptr))
                when {
                    header == null || top == null || !program.isRttiPointer(header.rtti) -> primary = null

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

    /**
     * Whether the words from [from] up to [until] are a few vbase, vcall and top offsets and rtti words, as a group
     * holds between tables: the header of a secondary with no slots of its own, a virtual base's, is all it has.
     */
    private fun onlyOffsetsBetween(from: Address, until: Address): Boolean {
        if (until < from) return false
        val words = (until - from) / ptr
        return words <= MAX_OFFSET_WORDS && (0 until words).all { i ->
            val word = until.wordBefore((words - i).toInt()) ?: return@all false
            abs(word) < MAX_SUBOBJECT_OFFSET || program.isRttiWord(until.subtractNoWrap((words - i) * ptr))
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
            val laid = listing.getDefinedDataContaining(table.addr)?.takeIf { it.isSeeded() }
            when {
                laid == null -> {}

                laid.address == table.addr -> {
                    if (laid.numComponents > table.slots.size) relay(laid, table.slots.size)
                    symtab.getSymbols(table.addr).firstOrNull { it.name == ClassNaming.VFTABLE && it.isSeededLabel() }
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

    /**
     * Settles the tables [seed] left where [parser] reads them otherwise: it moves those that are other classes'
     * secondary tables there ([regroup]), then seeds a class from each construction vtable no class holds the
     * slots of ([seedConstruction]). Returns how many tables it moved or seeded.
     */
    fun settle(parser: PlainVtableParser, monitor: TaskMonitor = TaskMonitor.DUMMY): Int {
        val misplaced = parser.misplacedTables(monitor)
        val moved = regroup(misplaced.secondaries)
        // Read again once a table moved: the classes it was seeded with are gone.
        val construction = (if (moved > 0) parser.misplacedTables(monitor) else misplaced).construction
        return moved + construction.count(::seedConstruction)
    }

    /**
     * Moves each seeded table in [secondaries] to the class it maps to, as that class's secondary table for the
     * base subobject at the mapped offset. The table is labelled and laid out in that class, and the class it was
     * seeded with is merged into it. Returns how many tables it moved.
     */
    private fun regroup(secondaries: Map<Address, Pair<GhidraClass, Long>>): Int {
        var moved = 0
        for ((at, target) in secondaries) {
            val (ns, offset) = target
            val label = symtab.getSymbols(at).firstOrNull { it.name == ClassNaming.VFTABLE && it.isSeededLabel() }
                ?: continue
            val seeded = label.parentNamespace as? GhidraClass ?: continue
            if (seeded == ns) continue
            val slots = listing.getDataAt(at)?.takeIf { it.isSeeded() }
                ?.let { d -> (0 until d.numComponents).mapNotNull { d.getComponent(it).value as? Address } }
                ?: continue
            label.delete()
            for (sym in symtab.getSymbols(seeded)) {
                runCatching { sym.setNamespace(ns) }.onFailure {
                    warn("vftable-regroup-member", "${sym.name} into ${ns.name}: $it", sym.address)
                }
            }
            if (!symtab.getSymbols(seeded).hasNext()) seeded.symbol.delete()
            val secondary = ClassNaming.plainSecondaryLabel(offset)
            symtab.createLabel(at, secondary, ns, SEEDED)
            listing.clearCodeUnits(at, at, false)
            lay(PotentialVtable(at, slots, emptyList()), ns, "${ns.name}_$secondary")
            debug("vftable-regrouped", "${seeded.name} as ${ns.name}'s, at +$offset", at)
            moved++
        }
        return moved
    }

    /**
     * Seeds the construction vtable at [table] as the `vftable` of a new class. Code never takes its address, but
     * a VTT points at it. The new class stands for the base the table is built for, whose slots it holds. Returns
     * whether it seeded a class. It doesn't when a table is already laid out or labelled at [table]. A base whose
     * only virtual thing is a virtual base has a table with no slots, which is labelled but not laid out: what
     * follows its address point is not its own, so may be laid out already.
     */
    private fun seedConstruction(table: Address): Boolean {
        if (symtab.getSymbols(table).any { it.source != SourceType.DEFAULT }) return false
        val slots = program.functionSlots(table, PlainVtables).toList()
        if (slots.isNotEmpty() && !isFree(table)) return false
        val ns = symtab.buildClassNamespaces(listOf("$SEEDED_CLASS_PREFIX$table"), SEEDED)
        symtab.createLabel(table, ClassNaming.VFTABLE, ns, SEEDED)
        if (slots.isNotEmpty()) lay(PotentialVtable(table, slots, emptyList()), ns)
        debug("vftable-seeded-construction", "${slots.size} slot(s), a VTT's", table)
        return true
    }

    /**
     * Lays a `<Class>_vftable` at [table], typed off its slots, unless one was typed already. A slot another
     * function's body holds only because it jumps there is made a function of its own first.
     */
    private fun lay(table: PotentialVtable, ns: GhidraClass, name: String? = null) {
        for (slot in table.slots) {
            program.splitOffTailJumpTarget(slot)?.let { debug("vftable-slot-split", "out of a tail jump", slot) }
        }
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
        (ClassNaming.isVftableLabel(it.name) && !it.isSeededLabel()) ||
            it.name == ClassNaming.VTABLE ||
            CxxAbi.ofVtableSymbol(it.name) != null
    }

    /**
     * Whether the word at [at] may be laid as a slot: nothing is laid there, or a word that is no struct or array,
     * or a table this finder seeded, which a later run may cut.
     */
    private fun isFree(at: Address): Boolean {
        val laid = listing.getDefinedDataContaining(at) ?: return true
        if (laid.isSeeded()) return true
        val dt = laid.baseDataType
        return laid.address == at && laid.length.toLong() == ptr && dt !is Composite && dt !is Array
    }

    /** Whether [laid] is a `<Class>_vftable` this finder laid, under its `vftable` label. */
    private fun Data.isSeeded() = dataType is Structure && symtab.getSymbols(address).any { it.isSeededLabel() }

    private fun Symbol.isSeededLabel() = ClassNaming.isClassVftableLabel(name) && source == SEEDED &&
        parentNamespace.name.startsWith(SEEDED_CLASS_PREFIX)

    private fun isNamed(at: Address) = symtab.getPrimarySymbol(at)
        ?.let { it.source != SourceType.DEFAULT && !it.isSeededLabel() } == true

    /**
     * Whether the word at [pfn] can be a slot pointing at [target]: an imported function's thunk, or code
     * ([isSlotCode], so not back into a read-only block its table shares with the code) where a function begins
     * or could, at an instruction's start or undisassembled; not inside a function, where a switch's jump table
     * points, unless the function only jumps there ([isTailJumpTarget]). MSVC ends a destructor with a jump to the
     * virtual after it, and Ghidra takes that virtual into the destructor's body.
     */
    private fun isSlot(pfn: Address, target: Address): Boolean {
        if (program.importedFunction(pfn, target) != null) return true
        if (!program.isSlotCode(pfn, target) || !program.isInitialized(target)) return false
        if (listing.getDefinedDataContaining(target) != null) return false
        if (listing.getInstructionContaining(target)?.let { it.address != target } == true) return false
        return program.functionManager.getFunctionContaining(target)
            ?.let { it.entryPoint == target || program.isTailJumpTarget(target) } ?: true
    }

    companion object {
        /** A seeded table's label and class source, an analysis', so a stabs import's or a user's names win. */
        val SEEDED = SourceType.ANALYSIS

        const val SEEDED_CLASS_PREFIX = "Klass_"

        /**
         * How many vbase and vcall offset words may sit between two tables of one group: a virtual base's secondary
         * has a vcall offset for each of its virtual functions, a dozen and more in a library's.
         */
        const val MAX_OFFSET_WORDS = 64L
    }
}
