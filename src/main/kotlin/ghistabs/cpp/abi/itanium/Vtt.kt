package ghistabs.cpp.abi.itanium

import ghidra.program.model.address.Address
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.listing.Program
import ghidra.program.model.scalar.Scalar
import ghistabs.Demangler
import ghistabs.cpp.leafName
import ghistabs.pointerAt
import ghistabs.valueAt

/**
 * A VTT word at [address]: a [comment] saying which vtable it points into, and for a sub-VTT's first, that
 * construction vtable's `_ZTC` name and its primary record's `offset_to_top` word.
 */
internal data class VttWord(val address: Address, val comment: String, val construction: Pair<String, Address>?)

/** A class's VTT, as its typeinfo lays it out. */
internal data class Vtt(val address: Address, val words: List<VttWord>) {
    val constructionVtables get() = words.mapNotNull { it.construction }
}

/**
 * Reads VTTs (ABI §2.6.2) off typeinfo alone, which fixes them once it is known which classes have a vptr.
 * For a class D with virtual bases a VTT holds, in order:
 *
 * 1. the address point of D's primary vtable;
 * 2. a sub-VTT for each direct non-virtual base with virtual bases, by these rules less step 4, starting
 *    with its construction vtable (`_ZTC<D><offset>_<B>`);
 * 3. the address point for each subobject, in inheritance graph order and each virtual base once, that has
 *    a vptr, has virtual bases or is reached through one, and isn't a non-virtual primary base;
 * 4. at the top only, a sub-VTT for each virtual base with virtual bases.
 *
 * A class has a vptr if it has virtual bases or a base with one, or if a primary vtable points at its
 * typeinfo ([dynamic]). Each word is checked against what it should point at, by the rtti word there.
 */
internal class VttReader(
    private val program: Program,
    private val rtti: Rtti.Reader,
    /** Each class typeinfo's mangled name (`N8CryptoPP9PublicKeyE`), by its address. */
    private val names: Map<Address, String>,
    /** The typeinfos a primary vtable points at, its own or a construction one. */
    private val dynamic: Set<Address>,
) {
    private val ptr = program.defaultPointerSize.toLong()
    private val word = IntegerDataType.getSignedDataType(program.defaultPointerSize, null)

    /** A subobject of the VTT's class, at [delta] from the nearest virtual base above it ([anchor]) or the class. */
    private inner class Subobject(val typeinfo: Address, val isVirtual: Boolean, val parent: Subobject?, delta: Long) {
        val name = names[typeinfo]
        val shown by lazy {
            Demangler.of(Itanium.TYPEINFO_NAME_PREFIX + name)?.originalDemangled?.substringAfter(" for ")?.leafName
        }
        val anchor: Subobject = if (isVirtual || parent == null) this else parent.anchor
        val delta: Long = if (isVirtual) 0 else delta
        val bases = mutableListOf<Subobject>()
        val hasVirtualBases: Boolean by lazy { bases.any { it.isVirtual || it.hasVirtualBases } }
        val isDynamic: Boolean by lazy { hasVirtualBases || typeinfo in dynamic || bases.any { it.isDynamic } }
        val isNonVirtualPrimary
            get() = !isVirtual && parent?.bases?.firstOrNull { !it.isVirtual && it.isDynamic } === this

        fun reachedVirtually(from: Subobject): Boolean =
            generateSequence(this) { it.parent }.takeWhile { it !== from }.any { it.isVirtual }
    }

    /** A VTT word: [subobject]'s address point in [owner]'s group, the first of [owner]'s sub-VTT if [head]. */
    private data class Entry(val owner: Subobject, val subobject: Subobject, val head: Boolean)

    /** [typeinfo]'s class and its bases, each virtual base once; null if a typeinfo on the way can't be read. */
    private fun hierarchy(typeinfo: Address): Subobject? {
        val virtuals = HashMap<Address, Subobject>()
        fun build(at: Address, isVirtual: Boolean, parent: Subobject?, delta: Long, depth: Int): Subobject? {
            val sub = Subobject(at, isVirtual, parent, delta)
            if (sub.name == null || depth > Rtti.MAX_BASE_DEPTH) return null
            for (base in rtti.basesOf(at) ?: return null) {
                sub.bases += when {
                    !base.isVirtual -> build(base.typeinfo, false, sub, sub.delta + base.offset, depth + 1)

                    else -> virtuals[base.typeinfo]
                        ?: build(base.typeinfo, true, sub, 0, depth + 1)?.also { virtuals[base.typeinfo] = it }
                } ?: return null
            }
            return sub
        }
        return build(typeinfo, false, null, 0, 0)
    }

    /** Each subobject under [root] in inheritance graph order, a virtual base where first reached. */
    private fun preorder(root: Subobject, descend: (Subobject) -> Boolean = { true }): List<Subobject> {
        val seen = HashSet<Subobject>()
        return buildList {
            fun walk(sub: Subobject) {
                if (!seen.add(sub)) return
                add(sub)
                if (descend(sub)) sub.bases.forEach(::walk)
            }
            walk(root)
        }
    }

    private fun MutableList<Entry>.addVtt(sub: Subobject, top: Boolean) {
        if (!sub.hasVirtualBases) return
        add(Entry(sub, sub, head = true))
        sub.bases.filterNot { it.isVirtual }.forEach { addVtt(it, top = false) }
        fun wanted(x: Subobject) = x.isDynamic && (x === sub || x.hasVirtualBases || x.reachedVirtually(sub))
        preorder(sub, ::wanted).filter { it !== sub && wanted(it) && !it.isNonVirtualPrimary }
            .forEach { add(Entry(sub, it, head = false)) }
        if (top) preorder(sub).filter { it.isVirtual }.forEach { addVtt(it, top = false) }
    }

    /** The `offset_to_top` word in front of what the VTT entry at [at] points at, and the rtti word. */
    private fun recordOf(at: Address): Pair<Address, Address?>? {
        val top = program.pointerAt(at)?.let { runCatching { it.subtractNoWrap(2 * ptr) }.getOrNull() } ?: return null
        return top to runCatching { program.pointerAt(top.add(ptr)) }.getOrNull()
    }

    private fun offsetToTop(top: Address) = program.valueAt<Scalar>(top, word)?.signedValue

    /** What [entry] points into, as `vtable for X-in-D` or `construction vtable for B-in-D`. */
    private fun comment(entry: Entry, root: Subobject): String {
        val owner = if (entry.owner === root) "${root.shown}" else "${entry.owner.shown}-in-${root.shown}"
        return when {
            entry.head && entry.owner === root -> "vtable for $owner"
            entry.head -> "construction vtable for $owner"
            entry.owner === root -> "vtable for ${entry.subobject.shown}-in-$owner"
            else -> "vtable for ${entry.subobject.shown}-in-$owner, in its construction vtable"
        }
    }

    /** The VTT at [at], or null if it isn't the one the typeinfo of the class its first word names describes. */
    fun vttAt(at: Address): Vtt? {
        val typeinfo = recordOf(at)?.second ?: return null
        val root = hierarchy(typeinfo)?.takeIf { it.hasVirtualBases } ?: return null
        val entries = buildList { addVtt(root, top = true) }

        val anchorOffset = hashMapOf(root to 0L)
        val records = entries.mapIndexed { i, entry ->
            val (record, rtti) = recordOf(at.add(i * ptr)) ?: return null
            val offset = offsetToTop(record) ?: return null
            if (rtti != entry.owner.typeinfo || (entry.head && offset != 0L)) return null
            if (entry.owner === root && entry.subobject.isVirtual) anchorOffset[entry.subobject] = -offset
            record
        }
        val words = entries.zip(records).mapIndexed { i, (entry, record) ->
            val sub = entry.subobject
            val construction = if (entry.head && entry.owner !== root) {
                val offset = (anchorOffset[sub.anchor] ?: return null) + sub.delta
                constructionVtableName(root.name ?: return null, offset, sub.name ?: return null)?.let { it to record }
            } else {
                null
            }
            VttWord(at.add(i * ptr), comment(entry, root), construction)
        }
        return Vtt(at, words)
    }
}

/** `S_`, `S0_`, `S1_`…: a back-reference to an earlier component of the same mangled name. */
private val SUBSTITUTION = Regex("S([0-9A-Z]*)_")

/**
 * The `_ZTC` name of the construction vtable for [base] at [offset] in [derived], given as their typeinfo
 * names, or null if none demangles to both. [base] follows [derived] in one name, so its substitutions
 * (`S5_`) are renumbered until it does. Where gcc would substitute what [derived] said, it is spelled out,
 * which demangles the same.
 */
internal fun constructionVtableName(derived: String, offset: Long, base: String): String? {
    fun demangled(type: String) =
        Demangler.of(Itanium.TYPEINFO_NAME_PREFIX + type)?.originalDemangled?.substringAfter(" for ")
    val want = "construction vtable for ${demangled(base) ?: return null}-in-${demangled(derived) ?: return null}"
    fun renumbered(by: Int) = SUBSTITUTION.replace(base) { ref ->
        val index = ref.groupValues[1].let { if (it.isEmpty()) 0 else it.toInt(36) + 1 } + by
        if (index == 0) "S_" else "S${(index - 1).toString(36).uppercase()}_"
    }
    val shifts = if (SUBSTITUTION.containsMatchIn(base)) 0..derived.length else 0..0
    return shifts.asSequence()
        .map { "${Itanium.CONSTRUCTION_VTABLE_PREFIX}$derived${offset}_${renumbered(it)}" }
        .firstOrNull { Demangler.of(it)?.originalDemangled == want }
}
