package ghicpp.abi.itanium

import ghicpp.abi.CxxAbi.Companion.prevailingAbi
import ghicpp.recover.findPointers
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghistabs.BoolOption
import ghistabs.Demangler
import ghistabs.cStringAt
import ghistabs.diagnose.DiagnosticSink
import ghistabs.get
import ghistabs.isData
import ghistabs.pointerAt
import ghistabs.set
import kotlin.ranges.rangeTo

/**
 * Puts back the `_ZTS`, `_ZTI`, `_ZTV`, `_ZTT` and `_ZTC` labels a stripped binary lost, which the rest of
 * the analysis finds vtables by, off the RTTI it kept:
 *
 * - a typeinfo is a pointer to its kind's vtable, in the binary or imported from libstdc++, then a pointer
 *   to a class's mangled name;
 * - its primary vtable is a 0, a pointer to that typeinfo, then a function pointer.
 *
 * A construction vtable has the same shape, so where several match, the VTTs say which those are, and the
 * PE section order, `_ZTC` before `_ZTV`, settles the rest; an ambiguous one is left. Only data blocks are
 * read, and an address already named is left alone, so an unstripped binary is untouched.
 */
class RttiSymbolPass(
    private val program: Program,
    sink: DiagnosticSink,
    /** With no mangled symbol to tell the ABI by, go ahead only on a name only Itanium spells. */
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
        program.findPointers()
            .filter { (src, dst) -> program.isData(dst) }
            .groupBy({ (_, dst) -> dst }) { (src, _) -> src }
    }

    /** The NUL-terminated class name at [addr], or null if what is there can't be one. */
    private fun className(addr: Address): String? =
        program.cStringAt(addr, 0..MAX_TYPE_NAME)?.takeIf(Itanium.CLASS_TYPE_NAME::matches)

    /** A class typeinfo at [address], whose `__type_name` is the [name] at [nameAddress]. */
    private data class TypeInfoRecord(val address: Address, val nameAddress: Address, val name: String)

    /** Whether this word points at data, or at an import, as a dynamically linked typeinfo's vtable is. */
    private fun Address.pointsToDataOrImport() = program.pointerAt(this)?.let { target ->
        program.isData(target) || memory.getBlock(target)?.isExternalBlock == true
    } == true

    /** Labels every class typeinfo, its name, and its vtable that lack one; returns how many vtables. */
    fun run(): Int {
        val names = HashMap<Address, String?>()
        val typeinfos = sitesByTarget.flatMap { (target, sites) ->
            val name = names.getOrPut(target) { className(target) } ?: return@flatMap emptyList()
            sites.mapNotNull { site -> site.plusWords(-1)?.takeIf { it.pointsToDataOrImport() } }
                .map { typeinfo -> TypeInfoRecord(typeinfo, target, name) }
        }.filter { Demangler.of(Itanium.TYPEINFO_PREFIX + it.name) != null }

        if (itaniumUnproven && typeinfos.none { Itanium.ITANIUM_ONLY_NAME.matches(it.name) }) return 0

        // A name two typeinfos claim can't say which is the class's own; neither is labelled.
        val unique = typeinfos.groupBy { it.name }.values.mapNotNull { it.singleOrNull() }
        for ((typeinfo, nameAt, name) in unique) {
            label(nameAt, Itanium.TYPEINFO_NAME_PREFIX + name)
            label(typeinfo, Itanium.TYPEINFO_PREFIX + name)
        }

        return labelVtables(unique)
    }

    /**
     * Labels the vtable of each class in [typeinfos], and the VTTs and construction vtables of those with
     * virtual bases; returns how many vtables. Classes one record matches go first; their VTTs then rule out
     * construction vtables among the rest.
     */
    private fun labelVtables(typeinfos: List<TypeInfoRecord>): Int {
        val header = dtm.vtableHeaderLayout(0)

        // The offset_to_top words in front of a pointer to this typeinfo that start a primary vtable.
        fun TypeInfoRecord.primaryVtables() = sitesByTarget[address]?.mapNotNull { it.plusWords(-1) }
            ?.filter { program.isPrimaryRecordAt(it, header) }.orEmpty()

        val candidates = typeinfos.associateWith { it.primaryVtables() }
        val rtti = TypeinfoReader(program)
        val reader = VttReader(
            program,
            rtti,
            names = typeinfos.associate { it.address to it.name },
            dynamic = candidates.filterValues { it.isNotEmpty() }.keys.mapTo(HashSet()) { it.address },
        )

        // A class's VTT is the lowest data word pointing at its address point: only VTTs hold vtable addresses
        // in data, and later entries can point there too.
        fun vttOf(top: Address) = top.plusWords(2)?.let(sitesByTarget::get)?.min()?.let(reader::vttAt)

        fun constructionIn(vtts: Collection<Vtt>) = vtts.flatMap { vtt -> vtt.constructionVtables.map { it.second } }

        // A class only ever built as a base, as `Up` in `Both` is, may have no vtable of its own: its one
        // match is then a construction vtable, which a settled class's VTT names.
        val single = candidates.mapNotNull { (ti, found) -> found.singleOrNull()?.let { ti to it } }.toMap()
        val named = constructionIn(single.values.mapNotNull(::vttOf)).toSet()
        val settled = single.filterValues { it !in named }
        var kept = labelVtables(settled, rtti)
        val vtts = settled.mapNotNull { (ti, top) -> vttOf(top)?.let { ti to it } }.toMap(HashMap())
        val construction = constructionIn(vtts.values).toSet()
        val among = settled.values.minOrNull()?.let { lo -> lo..settled.values.max() }
        val rest = candidates.filterKeys { it !in settled }.mapNotNull { (ti, found) ->
            val left = found - construction
            val top = left.singleOrNull() ?: left.singleOrNull { among != null && it in among } ?: run {
                if (found.isNotEmpty()) debug("vtable-rtti-ambiguous", "${ti.name}: $found", ti.address)
                return@mapNotNull null
            }
            ti to top
        }.toMap()
        kept += labelVtables(rest, rtti)
        rest.forEach { (ti, top) -> vttOf(top)?.let { vtts[ti] = it } }
        vtts.forEach { (ti, vtt) -> labelVtt(ti.name, vtt, rtti) }
        return kept
    }

    /** Labels [vtt], the VTT of the class [name] mangles, and the construction vtables it starts sub-VTTs with. */
    private fun labelVtt(name: String, vtt: Vtt, rtti: TypeinfoReader) {
        if (label(vtt.address, Itanium.VTABLE_TABLE_PREFIX + name)) debug("vtt-from-rtti", name, vtt.address)
        for ((ztc, top) in vtt.constructionVtables) {
            val base = program.pointerAt(top.add(ptr.toLong())) ?: continue
            val start = recordStart(top, base, rtti)
            if (label(start, ztc)) debug("vtable-construction-from-vtt", ztc, start)
        }
    }

    /**
     * Labels each class's vtable in [tops] where its record starts, moved back over zero vbase offsets once
     * the typeinfo says where they are; returns how many.
     */
    private fun labelVtables(tops: Map<TypeInfoRecord, Address>, rtti: TypeinfoReader): Int =
        tops.map { (ti, top) -> Triple(ti, top, program.recordStart(top)) }
            .filter { (ti, _, start) -> label(start, Itanium.VTABLE_PREFIX + ti.name) }
            .count { (ti, top, start) ->
                val vbaseStart = recordStart(top, ti.address, rtti)
                if (vbaseStart == start) {
                    debug("vtable-from-rtti", ti.name, start)
                    return@count true
                }
                program.symbolTable.getSymbol(Itanium.VTABLE_PREFIX + ti.name, start, null)?.delete()
                label(vbaseStart, Itanium.VTABLE_PREFIX + ti.name).also {
                    if (it) debug("vtable-rtti-zero-vbase", ti.name, vbaseStart)
                }
            }

    /** Where the record whose `offset_to_top` is at [top] starts, given the [typeinfo] its rtti word holds. */
    private fun recordStart(top: Address, typeinfo: Address, rtti: TypeinfoReader): Address {
        val start = program.recordStart(top)
        val lowest = rtti.virtualBasesOf(typeinfo).minOfOrNull { it.offset }
        return lowest?.let { top.plusWords(2)?.plusOrNull(it) }?.takeIf { it < start } ?: start
    }

    /** Labels [addr] with [name] unless anything named it already; whether it did. */
    private fun label(addr: Address, name: String): Boolean {
        if (program.symbolTable.getSymbols(addr).any { it.source != SourceType.DEFAULT }) return false
        program.symbolTable.createLabel(addr, name, SourceType.ANALYSIS)
        return true
    }

    companion object {
        val RTTI_SYMBOLS_RESTORED = BoolOption("RTTI Symbols Restored", "Stripped RTTI labels already put back.", false)

        /** The longest typeinfo name read. */
        private const val MAX_TYPE_NAME = 4096

        /**
         * [run] once, on a binary that may be Itanium, for [ghicpp.entrypoints.RttiSymbolAnalyzer].
         * Returns how many vtables were labelled.
         */
        fun runOnce(program: Program, sink: DiagnosticSink): Int {
            if (program[RTTI_SYMBOLS_RESTORED]) return 0
            program[RTTI_SYMBOLS_RESTORED] = true
            val abi = program.symbolTable.prevailingAbi()
            if (abi != null && abi != Itanium) return 0
            return RttiSymbolPass(program, sink, itaniumUnproven = abi == null).run()
        }
    }
}
