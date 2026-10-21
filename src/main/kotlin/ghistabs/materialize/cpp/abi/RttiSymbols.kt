package ghistabs.materialize.cpp.abi

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghistabs.BoolOption
import ghistabs.Demangler
import ghistabs.alignTo
import ghistabs.cStringAt
import ghistabs.cursorAt
import ghistabs.diagnose.DiagnosticSink
import ghistabs.get
import ghistabs.isData
import ghistabs.materialize.cpp.abi.CxxAbi.Companion.prevailingAbi
import ghistabs.nextPointer
import ghistabs.pointerAt
import ghistabs.seek
import ghistabs.set

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

    private fun Address.plusWords(n: Int): Address? = plusOrNull(n.toLong() * ptr)
    private fun Address.plusOrNull(by: Long): Address? = runCatching { addNoWrap(by) }.getOrNull()

    /** Every aligned word in the data blocks that points into them, by what it points at. */
    private val sitesByTarget: Map<Address, List<Address>> by lazy {
        val buf = program.cursorAt(memory.minAddress)
        buildMap<Address, MutableList<Address>> {
            for (b in memory.blocks.filter { it.isInitialized && !it.isExecute && it.start.addressSpace == space }) {
                buf.seek(b.start.alignTo(ptr.toLong()))
                while (buf.address in b) {
                    val site = buf.address
                    (buf.nextPointer() ?: break).takeIf(program::isData)?.let { target ->
                        getOrPut(target) { mutableListOf() }.add(site)
                    }
                }
            }
        }
    }

    /** The NUL-terminated class name at [addr], or null if what is there can't be one. */
    private fun className(addr: Address): String? =
        program.cStringAt(addr, 0..MAX_TYPE_NAME)?.takeIf(Itanium.CLASS_TYPE_NAME::matches)

    /** A class typeinfo at [address], whose `__type_name` is the [name] at [nameAddress]. */
    private data class TypeInfoRecord(val address: Address, val nameAddress: Address, val name: String)

    private fun Address.pointsToData() = program.pointerAt(this)?.let(program::isData) == true

    /** Labels every class typeinfo, its name, and its vtable that lack one; returns how many vtables. */
    fun restore(): Int {
        val names = HashMap<Address, String?>()
        val typeinfos = sitesByTarget.flatMap { (target, sites) ->
            val name = names.getOrPut(target) { className(target) } ?: return@flatMap emptyList()
            sites.mapNotNull { site -> site.plusWords(-1)?.takeIf { it.pointsToData() } }
                .map { typeinfo -> TypeInfoRecord(typeinfo, target, name) }
        }.filter { Demangler.of(Itanium.TYPEINFO_PREFIX + it.name) != null }

        if (itaniumUnproven && typeinfos.none { Itanium.ITANIUM_ONLY_NAME.matches(it.name) }) return 0

        // A name two typeinfos claim can't say which is the class's own; neither is labelled.
        val unique = typeinfos.groupBy { it.name }.values.mapNotNull { it.singleOrNull() }
        for ((typeinfo, nameAt, name) in unique) {
            label(nameAt, Itanium.TYPEINFO_NAME_PREFIX + name)
            label(typeinfo, Itanium.TYPEINFO_PREFIX + name)
        }

        val header = primaryHeader(dtm)

        // The offset_to_top words in front of a pointer to this typeinfo that start a primary vtable
        fun TypeInfoRecord.primaryVtables() = sitesByTarget[address]?.mapNotNull { it.plusWords(-1) }
            ?.filter { program.primaryRecordAt(it, header) != null }.orEmpty()

        val tops = unique.associate { it.name to (it.address to it.primaryVtables()) }
        val settled = tops.values.mapNotNull { (_, candidates) -> candidates.singleOrNull() }
        val among = settled.minOrNull()?.let { lo -> lo..settled.max() }
        val laid = tops.mapNotNull { (name, found) ->
            val (typeinfo, candidates) = found
            val top = candidates.singleOrNull()
                ?: candidates.singleOrNull { among != null && it in among } ?: run {
                if (candidates.isNotEmpty()) debug("vtable-rtti-ambiguous", "$name: $candidates", typeinfo)
                return@mapNotNull null
            }
            if (!label(program.recordStart(top), Itanium.VTABLE_PREFIX + name)) return@mapNotNull null
            Triple(name, typeinfo, top)
        }
        // Once every typeinfo and vtable is labelled, the typeinfos can be read for where they put their
        // vbase offsets, which a run of zeros in front of offset_to_top hides. Where the true start was
        // named all along (an unstripped binary), the label just laid is a duplicate and goes.
        val rtti = Rtti.Reader(program)
        val kept = laid.filter { (name, typeinfo, top) ->
            val start = program.recordStart(top)
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

    /**
     * Labels [addr] with [name] unless something already named it — mangled or, once the loader
     * demangled it, `vtable` — so only what stripping lost is put back. Whether it did.
     */
    private fun label(addr: Address, name: String): Boolean {
        if (program.symbolTable.getSymbols(addr).any { it.source != SourceType.DEFAULT }) return false
        program.symbolTable.createLabel(addr, name, SourceType.ANALYSIS)
        return true
    }

    companion object {
        val RTTI_SYMBOLS_RESTORED = BoolOption("RTTI Symbols Restored", "Stripped RTTI labels already put back.", false)

        /** Longest typeinfo name read; CryptoPP's deepest template instantiations run to a few hundred bytes. */
        private const val MAX_TYPE_NAME = 4096

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
}
