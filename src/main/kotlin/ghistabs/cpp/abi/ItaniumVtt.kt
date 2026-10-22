package ghistabs.cpp.abi

import ghidra.program.model.address.Address
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.listing.Program
import ghidra.program.model.scalar.Scalar
import ghistabs.Demangler
import ghistabs.pointerAt
import ghistabs.valueAt

/**
 * A class's VTT as its typeinfo lays it out: where it is, and the construction vtables its sub-VTTs start
 * with, each as its `_ZTC` name ([constructionVtableName]) and the `offset_to_top` word of its primary record.
 */
internal data class Vtt(val address: Address, val constructionVtables: List<Pair<String, Address>>)

/**
 * Reads VTTs (ABI §2.6.2) off typeinfo alone. A VTT is fixed by the class hierarchy: given which classes
 * have a vptr, the typeinfos say how many words it has and what each one points at. For a class D with
 * virtual bases it holds, in order:
 *
 * 1. the address point of D's primary vtable;
 * 2. a sub-VTT for each direct non-virtual base with virtual bases, built by these rules less step 4,
 *    starting with that base's construction vtable (`_ZTC<D><offset>_<B>`);
 * 3. the address point of the vtable for each subobject, in inheritance graph order and each virtual
 *    base once, that has a vptr, has virtual bases or is reached through a virtual base, and isn't a
 *    non-virtual primary base;
 * 4. at the top level only, a sub-VTT for each virtual base with virtual bases.
 *
 * Which classes have a vptr is the one thing typeinfo doesn't say: a class with virtual bases or a base
 * with a vptr has one, and a class with only virtuals of its own is known by a primary vtable pointing at
 * its typeinfo ([dynamic]). Gcc's VTTs follow these rules on every crypto_mi, xmltest and locale_test VTT.
 *
 * The VTT is the lowest data word pointing at D's address point: only a VTT stores a vtable address in data,
 * and a virtual primary base reusing D's vptr puts the same address a few words further into it. Each word
 * is checked against what the rules say it is for, by the rtti word in front of what it points at.
 */
internal class VttReader(
    private val program: Program,
    private val rtti: Rtti.Reader,
    /** Each class typeinfo's mangled name, `N8CryptoPP9PublicKeyE`. */
    private val names: Map<Address, String>,
    /** The typeinfos a primary vtable points at, its own or a construction one. */
    private val dynamic: Set<Address>,
    /** Every data word pointing into data, by what it points at. */
    private val sitesByTarget: Map<Address, List<Address>>,
) {
    private val ptr = program.defaultPointerSize.toLong()
    private val word = IntegerDataType.getSignedDataType(program.defaultPointerSize, null)

    /** One subobject of the class a VTT is for, at [delta] from the nearest virtual one ([anchor]) or the class. */
    private inner class Subobject(val typeinfo: Address, val isVirtual: Boolean, val parent: Subobject?, delta: Long) {
        val name = names[typeinfo]
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

    /** One VTT word: the address point of [subobject]'s vtable in [owner]'s group, the first of [owner]'s if [head]. */
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

    /** What the VTT entry at [at] points at: the `offset_to_top` word in front of the address point, and the rtti. */
    private fun recordOf(at: Address): Pair<Address, Address?>? {
        val top = program.pointerAt(at)?.let { runCatching { it.subtractNoWrap(2 * ptr) }.getOrNull() } ?: return null
        return top to runCatching { program.pointerAt(top.add(ptr)) }.getOrNull()
    }

    private fun offsetToTop(top: Address) = program.valueAt<Scalar>(top, word)?.signedValue

    /**
     * The VTT of the class with [typeinfo], whose primary vtable has its `offset_to_top` at [top], or null if
     * it has none, or what is there isn't the VTT its typeinfo describes.
     */
    fun vttOf(typeinfo: Address, top: Address): Vtt? {
        val root = hierarchy(typeinfo)?.takeIf { it.hasVirtualBases } ?: return null
        val at = sitesByTarget[top.add(2 * ptr)]?.min() ?: return null
        val entries = buildList { addVtt(root, top = true) }

        val anchorOffset = hashMapOf(root to 0L)
        val records = entries.mapIndexed { i, entry ->
            val (record, rtti) = recordOf(at.add(i * ptr)) ?: return null
            val offset = offsetToTop(record) ?: return null
            if (rtti != entry.owner.typeinfo || (entry.head && offset != 0L)) return null
            if (entry.owner === root && entry.subobject.isVirtual) anchorOffset[entry.subobject] = -offset
            record
        }
        val constructions = entries.zip(records).filter { (entry, _) -> entry.head && entry.owner !== root }
            .mapNotNull { (entry, record) ->
                val sub = entry.subobject
                val offset = (anchorOffset[sub.anchor] ?: return null) + sub.delta
                constructionVtableName(root.name ?: return null, offset, sub.name ?: return null)?.let { it to record }
            }
        return Vtt(at, constructions)
    }
}

/** `S_`, `S0_`, `S1_`…: a back-reference to an earlier component of the same mangled name. */
private val SUBSTITUTION = Regex("S([0-9A-Z]*)_")

/**
 * The `_ZTC` name of the construction vtable for [base] at [offset] in [derived], both mangled as their
 * typeinfo names spell them, or null if no spelling demangles to both.
 *
 * Gcc writes [base] after [derived] in one name, so [base]'s own substitutions count past every component
 * [derived] put in the table: appended as is, `DL_GroupParametersImpl<…, DL_GroupParameters<ECPPoint>>`'s
 * `S5_` names a component of `DL_GroupParameters_EC<ECP>` instead (crypto_mi). They are renumbered by each
 * count in turn until the name demangles to [base] in [derived]. The rest of [base] is spelled out where gcc
 * substitutes what [derived] already said (`…0_St13basic_istreamIwSt11char_traitsIwEE` for gcc's
 * `…0_St13basic_istreamIwS1_E`); it demangles the same.
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
