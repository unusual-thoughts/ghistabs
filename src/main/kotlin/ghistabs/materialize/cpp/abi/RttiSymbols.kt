package ghistabs.materialize.cpp.abi

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.MemoryBlock
import ghidra.program.model.symbol.SourceType
import ghistabs.Demangler
import ghistabs.diagnose.DiagnosticSink
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
class RttiSymbols(private val program: Program, sink: DiagnosticSink) : DiagnosticSink by sink {
    private val ptr = program.defaultPointerSize
    private val bigEndian = program.language.isBigEndian
    private val space = program.addressFactory.defaultAddressSpace
    private val data = program.memory.blocks.filter { it.isInitialized && !it.isExecute }.map(::Bytes)
    private val code = program.memory.blocks.filter { it.isExecute }.map { it.start.offset..it.end.offset }

    private class Bytes(block: MemoryBlock) {
        val start = block.start.offset
        val bytes = ByteArray(block.size.toInt()).also { block.getBytes(block.start, it) }
        operator fun contains(offset: Long) = offset - start in bytes.indices
    }

    /** The word at [offset], unsigned, or null outside the data blocks. */
    private fun word(offset: Long): Long? = data.firstOrNull { offset in it && offset + ptr - 1 in it }?.let { b ->
        val at = (offset - b.start).toInt()
        (0 until ptr).fold(0L) { acc, i ->
            val byte = b.bytes[at + if (bigEndian) i else ptr - 1 - i].toLong() and 0xff
            (acc shl 8) or byte
        }
    }

    /** [word], sign-extended from the pointer width. */
    private fun signedWord(offset: Long) = word(offset)?.let { if (ptr == 4) it.toInt().toLong() else it }

    private fun isData(offset: Long) = data.any { offset in it }

    private fun isCode(offset: Long) = code.any { offset in it }

    /** Every aligned word in the data blocks that points into them, by what it points at. */
    private val sitesByTarget: Map<Long, List<Long>> by lazy {
        val sites = HashMap<Long, MutableList<Long>>()
        for (b in data) {
            val first = b.start + (ptr - b.start % ptr) % ptr
            for (site in first..b.start + b.bytes.size - ptr step ptr.toLong()) {
                val target = word(site) ?: continue
                if (isData(target)) sites.getOrPut(target) { mutableListOf() }.add(site)
            }
        }
        sites
    }

    /** The NUL-terminated class name at [offset], or null if what is there can't be one. */
    private fun className(offset: Long): String? {
        val b = data.firstOrNull { offset in it } ?: return null
        val from = (offset - b.start).toInt()
        val end = (from until minOf(b.bytes.size, from + MAX_TYPE_NAME)).firstOrNull { b.bytes[it] == 0.toByte() }
            ?: return null
        return String(b.bytes, from, end - from, Charsets.ISO_8859_1).takeIf(CLASS_TYPE_NAME::matches)
    }

    /** Labels every class typeinfo, its name, and its vtable that lack one; returns how many vtables. */
    fun restore(): Int {
        val names = HashMap<Long, String?>()
        val typeinfos = sitesByTarget.flatMap { (target, sites) ->
            val name = names.getOrPut(target) { className(target) } ?: return@flatMap emptyList()
            sites.filter { site -> word(site - ptr)?.let(::isData) == true }
                .map { site -> Triple(site - ptr, target, name) }
        }.filter { (_, _, name) -> Demangler.of(Itanium.TYPEINFO_PREFIX + name) != null }
        // A name two typeinfos claim can't say which is the class's own; neither is labelled.
        val unique = typeinfos.groupBy { it.third }.values.mapNotNull { it.singleOrNull() }
        for ((typeinfo, nameAt, name) in unique) {
            label(nameAt, Itanium.TYPEINFO_NAME_PREFIX + name)
            label(typeinfo, Itanium.TYPEINFO_PREFIX + name)
        }
        val tops = unique.associate { (typeinfo, _, name) -> name to (typeinfo to primaryCandidates(typeinfo)) }
        val settled = tops.values.mapNotNull { (_, candidates) -> candidates.singleOrNull() }
        val among = (settled.minOrNull() ?: 0L)..(settled.maxOrNull() ?: 0L)
        val laid = tops.mapNotNull { (name, found) ->
            val (typeinfo, candidates) = found
            val top = candidates.singleOrNull() ?: candidates.filter { it in among }.singleOrNull() ?: run {
                if (candidates.isNotEmpty()) {
                    debug("vtable-rtti-ambiguous", "$name: ${candidates.map(::at)}", at(typeinfo))
                }
                return@mapNotNull null
            }
            val start = prefixStart(top)
            if (!label(start, Itanium.VTABLE_PREFIX + name)) return@mapNotNull null
            debug("vtable-from-rtti", name, at(start))
            Triple(name, typeinfo, top)
        }
        // Once every typeinfo and vtable is labelled, the typeinfos can be read for where they put their
        // vbase offsets, which a run of zeros in front of offset_to_top hides.
        val reader = Rtti.Reader(program)
        for ((name, typeinfo, top) in laid) {
            val lowest = reader.virtualBasesOf(at(typeinfo)).minOfOrNull { it.offset } ?: continue
            val start = prefixStart(top)
            val vbaseStart = top + 2L * ptr + lowest
            if (vbaseStart >= start) continue
            program.symbolTable.getSymbol(Itanium.VTABLE_PREFIX + name, at(start), null)?.delete()
            label(vbaseStart, Itanium.VTABLE_PREFIX + name)
            debug("vtable-rtti-zero-vbase", name, at(vbaseStart))
        }
        return laid.size
    }

    /**
     * The `offset_to_top` words a record of [typeinfo] can start its address point behind: a 0, then
     * a function pointer after the rtti word. Without that slot, `{0, typeinfo}` is as likely an exception
     * table's entry for a class with no vtable at all (`std::string` on crypto_mi), so a class whose
     * only virtual parts are its bases, and whose record has no slots, isn't found this way.
     */
    private fun primaryCandidates(typeinfo: Long): List<Long> = sitesByTarget[typeinfo].orEmpty()
        .map { it - ptr }
        .filter { top -> word(top) == 0L && word(top + 2L * ptr)?.let(::isCode) == true }

    /** Where the record whose `offset_to_top` is at [top] starts: in front of the vbase offsets it can see. */
    private fun prefixStart(top: Long) = generateSequence(top) { it - ptr }
        .drop(1)
        .takeWhile { at -> signedWord(at)?.let { it != 0L && abs(it) < MAX_VBASE_OFFSET && !isCode(it) } == true }
        .lastOrNull() ?: top

    private fun at(offset: Long): Address = space.getAddress(offset)

    /**
     * Labels [offset] with [name] unless something already named it — mangled or, once the loader
     * demangled it, `vtable` — so only what stripping lost is put back. Whether it did.
     */
    private fun label(offset: Long, name: String): Boolean {
        val addr = at(offset)
        if (program.symbolTable.getSymbols(addr).any { it.source != SourceType.DEFAULT }) return false
        program.symbolTable.createLabel(addr, name, SourceType.ANALYSIS)
        return true
    }
}
