package ghistabs.materialize.cpp.abi

import ghidra.program.model.address.Address
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.listing.Program
import ghidra.program.model.scalar.Scalar
import ghidra.program.model.symbol.SourceType
import ghistabs.BoolOption
import ghistabs.Demangler
import ghistabs.alignTo
import ghistabs.cStringAt
import ghistabs.cursorAt
import ghistabs.dataAt
import ghistabs.diagnose.DiagnosticSink
import ghistabs.get
import ghistabs.materialize.cpp.abi.CxxAbi.Companion.prevailingAbi
import ghistabs.nextData
import ghistabs.pointerAt
import ghistabs.seek
import ghistabs.set
import ghistabs.valueAt
import ghistabs.valueOf
import kotlin.math.abs

/** Longest typeinfo name read; CryptoPP's deepest template instantiations run to a few hundred bytes. */
private const val MAX_TYPE_NAME = 4096

/** Bound on a vbase offset, past which a word in front of `offset_to_top` is taken to be something else. */
private const val MAX_VBASE_OFFSET = 0x10000L

/** What an Itanium typeinfo name can spell for a class: `9TiXmlNode`, `N8CryptoPP3AESE`, `St9exception`. */
private val CLASS_TYPE_NAME = Regex("[0-9NS][A-Za-z0-9_]*")

/**
 * Puts back the `_ZTS`/`_ZTI`/`_ZTV` labels a stripped binary lost, from the RTTI it kept (§99). Everything
 * downstream finds a class's vtable by its `_ZTV` symbol and a record's rtti word by a `_ZTI` one, so a
 * stripped twin laid none. The chain each label hangs off:
 *
 * - a typeinfo is `{vptr, __type_name, …}`: a word pointing at a class's mangled name, with a pointer
 *   in front of it;
 * - its vtable's primary record is `{…, offset_to_top = 0, rtti, slot 0, …}`: a word pointing at that
 *   typeinfo, behind a 0 and ahead of a function pointer.
 *
 * Several records can match the second shape: a construction vtable (`_ZTC`) puts a base's typeinfo
 * behind a 0 too, and a constructor can store its address point as readily as the class's own. The
 * PE linker sorts `.rdata$_ZTC…` ahead of `.rdata$_ZTV…`, so the class's own record is the one among
 * the vtables only one record matched; none is taken if that still leaves more than one.
 *
 * A record's vbase offsets sit in front of `offset_to_top` and are walked back over while they are small
 * and non-zero. A vbase offset of 0 (a nearly-empty primary virtual base) can't be told from padding;
 * the typeinfo says where its word is, so the start is moved back over it once the typeinfos read.
 *
 * Only reads non-executable blocks for the RTTI: an old i386 ELF linking `.rodata` into text has its
 * symbols anyway. Leaves any address something already named alone, so an unstripped binary is untouched.
 */
class RttiSymbols(
    private val program: Program,
    sink: DiagnosticSink,
    /** With no mangled symbol to tell the ABI by, only go ahead once a name only Itanium spells turns up. */
    private val itaniumUnproven: Boolean = false,
) : DiagnosticSink by sink {
    private val ptr = program.defaultPointerSize
    private val space = program.addressFactory.defaultAddressSpace
    private val memory = program.memory
    private val dtm = program.dataTypeManager

    private val pointer = PointerDataType(dtm)

    private fun Address.isData() = memory.getBlock(this)?.let { it.isInitialized && !it.isExecute } == true

    private fun Address.isCode() = memory.getBlock(this)?.isExecute == true

    private fun Address.plusWords(n: Int): Address? = plusOrNull(n.toLong() * ptr)

    private fun Address.plusOrNull(by: Long): Address? = runCatching { addNoWrap(by) }.getOrNull()

    private fun signedWord(addr: Address) =
        program.valueAt<Scalar>(addr, IntegerDataType.getSignedDataType(ptr, null))?.signedValue

    /** Every aligned word in the data blocks that points into them, by what it points at. */
    private val sitesByTarget: Map<Address, List<Address>> by lazy {
        val buf = program.cursorAt(memory.minAddress)
        buildMap<Address, MutableList<Address>> {
            for (b in memory.blocks.filter { it.isInitialized && !it.isExecute && it.start.addressSpace == space }) {
                buf.seek(b.start.alignTo(ptr.toLong()))
                while (buf.address.plusOrNull(ptr - 1L)?.let(b::contains) == true) {
                    val data = buf.nextData(pointer) ?: break
                    val addr = (data.value as? Address)?.takeIf { it.isData() } ?: continue
                    getOrPut(addr) { mutableListOf() }.add(data.address)
                }
            }
        }
    }

    /** The NUL-terminated class name at [addr], or null if what is there can't be one. */
    private fun className(addr: Address): String? =
        program.cStringAt(addr, 0..MAX_TYPE_NAME)?.takeIf(CLASS_TYPE_NAME::matches)

    companion object {
        val RTTI_SYMBOLS_RESTORED = BoolOption("RTTI Symbols Restored", "Stripped RTTI labels already put back.", false)

        /** Typeinfo names only Itanium spells: a nested name, or one in `std`. gcc 2.x writes `Q2…`, `9type_info`. */
        private val ITANIUM_ONLY_NAME = Regex("N.*E|St.*")

        /**
         * [restore] on an Itanium binary, once: early analysis does it ([ghistabs.entrypoints.RttiSymbolsAnalyzer]),
         * and a stabs import run before analysis does it itself. gcc 2.x builds its typeinfo at run time, so a
         * name string in its data proves nothing; a stripped binary may have no mangled symbol left to say which
         * ABI it is, and then a name only Itanium spells has to. Returns how many vtables were labelled.
         */
        fun restoreOnce(program: Program, sink: DiagnosticSink): Int {
            if (program[RTTI_SYMBOLS_RESTORED]) return 0
            program[RTTI_SYMBOLS_RESTORED] = true
            val abi = program.symbolTable.prevailingAbi()
            if (abi != null && abi != Itanium) return 0
            return RttiSymbols(program, sink, itaniumUnproven = abi == null).restore()
        }
    }

    /** Labels every class typeinfo, its name, and its vtable that lack one; returns how many vtables. */
    fun restore(): Int {
        val names = HashMap<Address, String?>()
        val typeinfos = sitesByTarget.flatMap { (target, sites) ->
            val name = names.getOrPut(target) { className(target) } ?: return@flatMap emptyList()
            sites.mapNotNull { site -> site.plusWords(-1)?.takeIf { program.pointerAt(it)?.isData() == true } }
                .map { typeinfo -> Triple(typeinfo, target, name) }
        }.filter { (_, _, name) -> Demangler.of(Itanium.TYPEINFO_PREFIX + name) != null }
        if (itaniumUnproven && typeinfos.none { ITANIUM_ONLY_NAME.matches(it.third) }) return 0
        // A name two typeinfos claim can't say which is the class's own; neither is labelled.
        val unique = typeinfos.groupBy { it.third }.values.mapNotNull { it.singleOrNull() }
        for ((typeinfo, nameAt, name) in unique) {
            label(nameAt, Itanium.TYPEINFO_NAME_PREFIX + name)
            label(typeinfo, Itanium.TYPEINFO_PREFIX + name)
        }
        val tops = unique.associate { (typeinfo, _, name) -> name to (typeinfo to primaryCandidates(typeinfo)) }
        val settled = tops.values.mapNotNull { (_, candidates) -> candidates.singleOrNull() }
        val among = settled.minOrNull()?.let { lo -> lo..settled.max() }
        val laid = tops.mapNotNull { (name, found) ->
            val (typeinfo, candidates) = found
            val top = candidates.singleOrNull()
                ?: candidates.singleOrNull { among != null && it in among } ?: run {
                if (candidates.isNotEmpty()) debug("vtable-rtti-ambiguous", "$name: $candidates", typeinfo)
                return@mapNotNull null
            }
            if (!label(prefixStart(top), Itanium.VTABLE_PREFIX + name)) return@mapNotNull null
            Triple(name, typeinfo, top)
        }
        // Once every typeinfo and vtable is labelled, the typeinfos can be read for where they put their
        // vbase offsets, which a run of zeros in front of offset_to_top hides. Where the true start was
        // named all along (an unstripped binary), the label just laid is a duplicate and goes.
        val rtti = Rtti.Reader(program)
        val kept = laid.filter { (name, typeinfo, top) ->
            val start = prefixStart(top)
            val lowest = rtti.virtualBasesOf(typeinfo).minOfOrNull { it.offset }
            val vbaseStart = lowest?.let { top.plusWords(2)?.plusOrNull(it) }?.takeIf { it < start }
            if (vbaseStart == null) {
                debug("vtable-from-rtti", name, start)
                return@filter true
            }
            program.symbolTable.getSymbol(Itanium.VTABLE_PREFIX + name, start, null)?.delete()
            label(vbaseStart, Itanium.VTABLE_PREFIX + name).also {
                if (it) debug("vtable-rtti-zero-vbase", name, vbaseStart)
            }
        }
        return kept.size
    }

    private val vtable by lazy { potentialVtable(dtm) }

    /**
     * The `offset_to_top` words a record of [typeinfo] can start its address point behind: a 0, then
     * a function pointer after the rtti word. Without that slot, `{0, typeinfo}` is as likely an exception
     * table's entry for a class with no vtable at all (`std::string` on crypto_mi), so a class whose
     * only virtual parts are its bases, and whose record has no slots, isn't found this way.
     */
    private fun primaryCandidates(typeinfo: Address): List<Address> = sitesByTarget[typeinfo].orEmpty()
        .mapNotNull { it.plusWords(-1)?.takeIf { top -> top.isData() } }
        .mapNotNull { program.dataAt(it, vtable) }
        .filter { it.valueOf<Scalar>(0)?.value == 0L }
        .filter { it.valueOf<Address>(2)?.isCode() == true }
        .map { it.address }

    /** Where the record whose `offset_to_top` is at [top] starts: in front of the vbase offsets it can see. */
    private fun prefixStart(top: Address) = generateSequence(top) { it.plusWords(-1) }
        .drop(1)
        .takeWhile { at -> signedWord(at)?.let { it != 0L && abs(it) < MAX_VBASE_OFFSET && !isCodeOffset(it) } == true }
        .lastOrNull() ?: top

    /** Whether a vbase-offset-sized [value] is rather a pointer into code. */
    private fun isCodeOffset(value: Long) = runCatching { space.getAddress(value) }.getOrNull()?.isCode() == true

    /**
     * Labels [addr] with [name] unless something already named it — mangled or, once the loader
     * demangled it, `vtable` — so only what stripping lost is put back. Whether it did.
     */
    private fun label(addr: Address, name: String): Boolean {
        if (program.symbolTable.getSymbols(addr).any { it.source != SourceType.DEFAULT }) return false
        program.symbolTable.createLabel(addr, name, SourceType.ANALYSIS)
        return true
    }
}
