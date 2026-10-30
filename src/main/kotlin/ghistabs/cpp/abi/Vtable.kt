package ghistabs.cpp.abi

import ghidra.app.util.demangler.DemangledObject
import ghidra.program.model.address.Address
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghistabs.*
import ghistabs.cpp.ClassNaming
import ghistabs.cpp.abi.itanium.Itanium
import ghistabs.cpp.abi.itanium.Rtti
import ghistabs.cpp.abi.itanium.startsVtableGroup
import ghistabs.cpp.abi.itanium.vtableOffsetField
import ghistabs.cpp.abi.msvc.msvcSubobjectOffset

/** How an ABI spells a vtable's symbol, and which class one names. */
interface VtableSymbols {
    /** Whether [symbolName] is one of this ABI's vtable symbols. */
    fun looksLikeVtable(symbolName: String): Boolean

    /**
     * Whether [symbolName] names a class's own table rather than a base's secondary one. Only gcc 2.x gives
     * secondaries symbols of their own.
     */
    fun isPrimaryVtable(symbolName: String) = looksLikeVtable(symbolName)

    /** The symbols [className]'s vtable may have, most likely first; none for a template, which has no closed form. */
    fun vtableCandidates(className: String): List<String>

    /** The qualified class [obj] is the vtable of, if it is one of this ABI's. */
    fun demangledVtableClass(obj: DemangledObject): String?
}

/** How an ABI lays out a vtable record. By default a header, then one pointer per slot from the address point. */
interface VtableLayout {
    /** Where a primary vptr sits in its object: 0, or null under gcc 2.x, where only the class struct says. */
    val primaryVptrOffset: Long? get() = 0L

    /** The record whose vtable symbol is at [at]. */
    fun recordAt(program: Program, at: Address): VtableRecord

    /** What a vptr into [record] holds, where its `_vftable` struct begins: by default right past its header. */
    fun addressPoint(record: VtableRecord): Address = record.address.add(record.header?.length?.toLong() ?: 0L)

    /** Where each slot's function pointer sits, in slot order, in bytes from the address point. */
    fun slotOffsets(ptrSize: Int): Sequence<Long> = generateSequence(0L) { it + ptrSize }

    /** How many entries before the first slot a stab's `*<n>` counts: none where the vptr is past the header. */
    fun reservedEntries(ptrSize: Int) = 0

    /**
     * The fields of gcc 2.x's reserved entry, at the front of the `_vftable` struct so the slots land at
     * their offsets. None is a pointer, which keeps them out of the slots.
     */
    fun Structure.addReservedHeader() = Unit

    /** The `{delta, index}` before slot [slot]'s pfn in a gcc 2.x entry without thunks; `delta` adjusts `this`. */
    fun Structure.addEntryAdjustment(slot: Int) = Unit

    /** Where the vptr into this record sits in the complete object, if the record says: Itanium's `-offset_to_top`. */
    fun VtableRecord.vfptrOffset(program: Program): Long? = null
}

/**
 * A vtable record ([vtableRecord]): where it starts, the [header] in front of its address point, and its [abi].
 * Only Itanium's has a header ([ghistabs.cpp.abi.itanium.vtableHeaderLayout]).
 */
data class VtableRecord(val address: Address, val header: StructureDataType?, val abi: CxxAbi) {
    /** The vbase/vcall-offset words in front of `offset_to_top` and the rtti pointer. */
    val prefixWords get() = header?.let { it.numComponents - 2 } ?: 0

    /** What a vptr into this record holds, where its `vftable` label goes. */
    val addressPoint: Address get() = abi.addressPoint(this)

    /** Where [header]'s field [name] sits in memory. */
    fun fieldAddress(name: String): Address? = header?.field(name)?.let { address.add(it.offset.toLong()) }

    private fun StructureDataType.field(name: String) = components.firstOrNull { it.fieldName == name }

    /** [header] as memory holds it, read through its layout; null for a gcc 2.x record. */
    fun readHeader(program: Program): Data? = header?.let { program.dataAt(address, it) }

    /**
     * The vbase offset this record keeps for virtual [base], at the header word [base]'s typeinfo offset
     * names, which is commented with [base]'s name. Null if that word is not in the header.
     */
    fun vbaseOffset(program: Program, base: Rtti.Reader.Base) = vtableOffsetField(
        ((addressPoint + base.offset - address) / program.defaultPointerSize).toInt(),
    ).let { field ->
        fieldAddress(field)?.let { program.listing.setComment(it, CommentType.EOL, "${base.className} vbase offset") }
        readHeader(program)?.getScalar(field)?.signedValue
    }

    /** The typeinfo the rtti word points at. */
    fun rttiOf(program: Program): Address? = readHeader(program)?.valueOf<Address>(Itanium.RTTI)

    /**
     * What header word [i] of [total] holds: vcall offsets, then one vbase offset per virtual base
     * (§2.5.2). Unsplit when the class states no virtual bases, or more than the words.
     */
    private fun prefixKind(i: Int, total: Int, virtualBases: List<String>): String {
        val vcalls = total - virtualBases.size
        if (virtualBases.isEmpty() || vcalls < 0) return "vbase/vcall offset"
        // Naming the word only when there is one virtual base to name. The ABI fixes the order of the
        // vbase offsets, but nothing here has verified it against a class with several, and a confidently
        // wrong base name in a comment is worse than none.
        return when {
            i < vcalls -> "vcall offset"
            virtualBases.size == 1 -> "vbase offset: ${virtualBases.single()}"
            else -> "vbase offset"
        }
    }

    /** Whether a vtable group's symbol sits on a header word: a walk through secondaries has left its group. */
    fun opensGroup(program: Program): Boolean =
        generateSequence(address) { it.add(program.defaultPointerSize.toLong()) }
            .takeWhile { it < addressPoint }
            .any { at -> program.symbolTable.getSymbols(at).any { startsVtableGroup(it.name) } }

    /**
     * The functions the slots point at, in order. Nothing records how many there are, so they end at the
     * first entry that isn't code or an imported function. Up to two nulls count when a function follows:
     * gcc 12 leaves an abstract class's destructor slots 0.
     */
    fun slots(program: Program): List<Address> = buildList {
        val ptr = program.defaultPointerSize
        val nulls = mutableListOf<Address>()
        for (pfn in abi.slotOffsets(ptr).map(addressPoint::add)) {
            val target = program.pointerAt(pfn) ?: break
            when {
                target.offset == 0L && nulls.size < DESTRUCTOR_SLOTS -> nulls += target

                program.isCode(target) || program.isImportedFunction(pfn, target) ->
                    addAll(nulls + target).also { nulls.clear() }

                else -> break
            }
        }
    }

    /**
     * Whether [pfn] is relocated against the imported function whose thunk is at [target]. Data imports share
     * the EXTERNAL block, so the thunk alone doesn't say: a typeinfo's vptr can land on one.
     */
    private fun Program.isImportedFunction(pfn: Address, target: Address): Boolean {
        val thunk = functionManager.getFunctionAt(target)?.takeIf { it.isThunk } ?: return false
        return relocationTable.getRelocations(pfn).any { it.symbolName == thunk.name }
    }

    /**
     * The rtti word's comment: the typeinfo symbol actually there, its linkage name over Ghidra's `typeinfo`
     * label, and only then [Itanium.zti]'s guess, which misses abbreviations such as `_ZTISi`.
     */
    private fun rttiComment(program: Program, className: String): String {
        val name = rttiOf(program)
            ?.let { program.symbolTable.getSymbols(it).map { s -> s.name } }
            ?.let { names -> names.firstOrNull(Itanium::looksLikeZti) ?: names.firstOrNull() }
            ?: Itanium.zti(className)
        return "$name typeinfo"
    }

    /**
     * Labels and lays this record as [ns]'s table in [role], and returns its address point, where the
     * [vftable] struct and the `vftable` label go. An Itanium header is laid in front, each word commented
     * with what it holds for [className], whose [virtualBases] name its vbase offsets. A gcc 2.x record
     * is only labelled.
     */
    fun lay(
        registry: DtmRegistry,
        program: Program,
        vftable: Structure?,
        className: String,
        ns: Namespace,
        role: VtableRole = VtableRole.PRIMARY,
        virtualBases: List<String> = emptyList(),
        source: SourceType = SourceType.IMPORTED,
    ): Address {
        val vftableLabel = role.vftableLabel
        // gcc 2.x declares the record itself (`__vtbl_ptr_type __vt_9TiXmlNode[20]`), which knows its length
        // better than anything here, and a virtual call resolves off the vptr's type, not the data there.
        if (header == null) {
            program.listing.setComment(address, CommentType.EOL, "gcc 2.x vtable: reserved entry, then the slots")
            program.labelVtable(address, vftableLabel, ns, source)
            return address
        }

        program.labelVtable(address, role.vtableLabel, ns, source)
        program.forceCreateData(address, registry.resolveLayout(header))
        for (i in 0 until prefixWords) {
            fieldAddress(vtableOffsetField(i))?.let {
                program.listing.setComment(it, CommentType.EOL, prefixKind(i, prefixWords, virtualBases))
            }
        }
        fieldAddress(Itanium.RTTI)?.let {
            program.listing.setComment(it, CommentType.EOL, rttiComment(program, className))
        }
        vftable?.let { program.forceCreateData(addressPoint, it) }
        program.labelVtable(addressPoint, vftableLabel, ns, source)
        return addressPoint
    }
}

/**
 * Which of a class's tables a record is: a secondary ([internal]), one in a `_ZTC` group ([construction]),
 * and the [base] it serves once the class has several. Its labels are Ghidra's ([ClassNaming.vftableLabel]).
 */
data class VtableRole(val internal: Boolean = false, val construction: Boolean = false, val base: String? = null) {
    val vtableLabel get() = ClassNaming.vtableLabel(internal, construction)
    val vftableLabel get() = ClassNaming.vftableLabel(internal, construction, base)

    companion object {
        val PRIMARY = VtableRole()
    }
}

/** gcc's two destructor entries, complete and deleting: the only slots it leaves null. */
private const val DESTRUCTOR_SLOTS = 2

/** The record whose vtable symbol is at [ztv], as [abi] finds it. */
fun Program.vtableRecord(ztv: Address, abi: CxxAbi = Itanium): VtableRecord = abi.recordAt(this, ztv)

/** Labels [at], raising an existing label to [SourceType.IMPORTED], which is what [isVtableClaimed] reads. */
private fun Program.labelVtable(at: Address, label: String, ns: Namespace, source: SourceType) {
    val sym = symbolTable.createLabel(at, label, ns, source)
    if (source == SourceType.IMPORTED && sym.source != source) sym.source = source
}

/** Renames [ns]'s [from] label at [at] to [to], or drops it for a [to] already there. */
fun Program.renameVtableLabel(at: Address, from: String, to: String, ns: Namespace) {
    if (from == to) return
    val here = symbolTable.getSymbols(at).filter { it.parentNamespace == ns }
    val old = here.firstOrNull { it.name == from } ?: return
    when (val existing = here.firstOrNull { it.name == to }) {
        null -> old.setName(to, old.source)

        else -> {
            if (old.source == SourceType.IMPORTED) existing.source = SourceType.IMPORTED
            old.delete()
        }
    }
}

/**
 * Whether [label], one of a class's vftable labels, marks its primary table. Once there are several, the
 * record says: an Itanium primary's header is `vtable`, not `internal_vtable`; a gcc 2.x primary has its
 * class's own `_vt` symbol; an MSVC one's complete object locator gives offset 0.
 */
fun Program.isPrimaryVftable(label: Symbol): Boolean =
    msvcSubobjectOffset(label.address)?.let { it == 0 } ?: when (label.name) {
        ClassNaming.VFTABLE -> true

        ClassNaming.vftableLabel(internal = true) -> false

        else -> listing.getDataBefore(label.address)?.takeIf { it.maxAddress.next() == label.address }
            ?.let { symbolTable.getSymbols(it.address) }.orEmpty()
            .any { it.name == ClassNaming.VTABLE && it.parentNamespace == label.parentNamespace } ||
            symbolTable.getSymbols(label.address).any {
                CxxAbi.ofVtableSymbol(it.name)?.isPrimaryVtable(it.name) == true
            }
    }

/**
 * The struct of the table [label] marks: the one laid there, or for gcc 2.x, which lays none, the one named
 * after the label: `<leaf>_vftable_for_<Base>`, or `<leaf>_vftable` or `<leaf>_vftable0` for `vftable`.
 */
fun Program.vftableStructAt(label: Symbol): Structure? {
    (listing.getDataAt(label.address)?.dataType as? Structure)?.takeIf { "_${ClassNaming.VFTABLE}" in it.name }
        ?.let { return it }
    val suffixes = when {
        label.name.startsWith(ClassNaming.vftableForLabel("")) -> listOf("_${label.name}")
        label.name == ClassNaming.VFTABLE -> listOf("_${ClassNaming.VFTABLE}", "_${ClassNaming.VFTABLE}0")
        else -> return null
    }
    val types = dataTypeManager.getCategory(ClassNaming.vftableCategory(label.parentNamespace))?.dataTypes.orEmpty()
    return suffixes.firstNotNullOfOrNull { suffix ->
        types.filterIsInstance<Structure>().firstOrNull { it.name.endsWith(suffix) }
    }
}

/**
 * Whether the stabs import already laid [record]: an [SourceType.IMPORTED] vftable label at its address
 * point. A sweep's labels are [SourceType.ANALYSIS], so a later sweep lays the table again.
 */
fun Program.isVtableClaimed(record: VtableRecord): Boolean = symbolTable.getSymbols(record.addressPoint)
    .any { it.source == SourceType.IMPORTED && ClassNaming.isClassVftableLabel(it.name) }

/** Where a class's vtable record is, and its ABI. */
data class ResolvedVtable(val className: String, val address: Address, val abi: CxxAbi) {
    companion object {
        /** [className]'s, if [symName] is a vtable symbol at all. */
        fun of(className: String, symName: String, addr: Address) =
            CxxAbi.ofVtableSymbol(symName)?.let { ResolvedVtable(className, addr, it) }

        /** The class whose own vtable [sym] is, demangled; null for a secondary or any other symbol. */
        fun fromSymbol(sym: Symbol) = CxxAbi.ofVtableSymbol(sym.name)
            ?.takeIf { it.isPrimaryVtable(sym.name) }
            ?.let { abi ->
                Demangler.of(sym.name)
                    ?.let(abi::demangledVtableClass)
                    ?.let { ResolvedVtable(it, sym.address, abi) }
            }
    }
}
