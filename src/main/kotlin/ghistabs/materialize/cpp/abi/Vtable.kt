package ghistabs.materialize.cpp.abi

import ghidra.program.model.address.Address
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghistabs.*
import ghistabs.materialize.DtmRegistry
import ghistabs.materialize.cpp.ClassNaming

/** Upper bound on vbase/vcall-offset words scanned before giving up on locating the rtti header. */
private const val MAX_VTABLE_PREFIX_WORDS = 64

/**
 * The pointer at [a], or null if it is unmapped or does not point into executable memory. The one test
 * that separates a vtable's function pointers from its header words — both scans below turn on it, and
 * neither can use symbol presence, which auto-analysis sprays `PTR_` labels across. An rtti word can
 * pass it too: an old i386 ELF links `.rodata`, typeinfo and all, into the R-X text segment, so the
 * scans exempt the rtti word before asking.
 *
 * Read as it stands, never through [ghistabs.harvest.AddressResolver.buildAddress]: that fixup is for
 * stab values, which nothing relocated, while the loader has already relocated what memory holds — a
 * PIE loaded at 0x10000 would otherwise have every vtable pointer moved another 0x10000 off its target.
 */
private fun Program.codeTargetAt(a: Address) = readPointer(a)?.takeIf { memory.getBlock(it)?.isExecute == true }

/** The header field holding an Itanium record's vbase/vcall-offset word [i], counted from the record start. */
fun vtableOffsetField(i: Int) = "vcall_vbase_offset_$i"

/**
 * The header of an Itanium vtable record with [prefixWords] vbase/vcall-offset words in front of
 * `offset_to_top` and the rtti pointer (ABI §2.5.2), one layout per prefix length the way
 * [Rtti.vmiClassTypeInfo] has one per base count. Unresolved, like [Rtti]'s: [vtableRecord] reads a
 * record through it without writing to the DTM, and [VtableRecord.lay] resolves it to lay one.
 */
fun vtableHeaderLayout(dtm: DataTypeManager, prefixWords: Int): StructureDataType {
    val word = Itanium.offsetToTopType(dtm.dataOrganization.pointerSize)
    val name = "VtableHeaderStructure${if (prefixWords > 0) prefixWords else ""}"
    return StructureDataType(ClassNaming.classDataTypesRoot, name, 0, dtm).apply {
        // One field a word, not an array: Ghidra shows no comment on a word inside an array inside a struct,
        // and each word gets its own saying which base it is for.
        repeat(prefixWords) { add(word, vtableOffsetField(it), null).showDecimal() }
        add(word, Itanium.OFFSET_TO_TOP, "to top of complete object").showDecimal()
        add(PointerDataType(dtm), Itanium.RTTI, null)
        isPackingEnabled = true
    }
}

fun potentialVtable(dtm: DataTypeManager) = StructureDataType("PossibleVtable", 0).apply {
    val word = Itanium.offsetToTopType(dtm.dataOrganization.pointerSize)
    add(word, Itanium.OFFSET_TO_TOP, "to top of complete object").showDecimal()
    add(PointerDataType(dtm), Itanium.RTTI, null)
    add(PointerDataType(dtm), "maybeMethod", null)
    isPackingEnabled = true
}

// interface Structable {
// //    val dt: StructureDataType
//     val data: Data
// }

// class VtableHeader(dtm: DataTypeManager, prefixWords: Int) :
//     StructureDataType(
//         ClassNaming.classDataTypesRoot,
//         "VtableHeaderStructure${if (prefixWords > 0) prefixWords else ""}",
//         0,
//         dtm,
//     ) {
//     init {
//         val word = Itanium.offsetToTopType(dtm.dataOrganization.pointerSize)
//         // One field a word, not an array: Ghidra shows no comment on a word inside an array inside a struct,
//         // and each word gets its own saying which base it is for.
//         repeat(prefixWords) { add(word, vtableOffsetField(it), null).showDecimal() }
//         add(word, Itanium.OFFSET_TO_TOP, "to top of complete object").showDecimal()
//         add(PointerDataType(dtm), Itanium.RTTI, null)
//         isPackingEnabled = true
//     }

//     @Suppress("ktlint:standard:property-naming")
//     class Value(override val data: Data) : Structable {
//         val offset_to_top by field<Scalar>()
//         val rtti by field<Address>()
//     }
// }

// interface Prout<T> {
//     operator fun getValue(thisRef: Structable, property: KProperty<*>): T?
// }

// inline fun <reified T> field() = object : Prout<T> {
//     override operator fun getValue(thisRef: Structable, property: KProperty<*>): T? =
//         thisRef.data[property.name]?.value as? T?
// }

// //
// class StructFieldDelegate<T : Any> {
//     operator fun getValue(thisRef: Structable, property: KProperty<*>): T? = thisRef.data[property.name]?.value as? T?
// }

// //    operator fun setValue(thisRef: Any?, property: KProperty<*>, value: String) {
// //        println("$value has been assigned to '${property.name}' in $thisRef.")
// //    }
// }
//
//
//
// class Thing(dtm: DataTypeManager) : StructureDataType(ClassNaming.classDataTypesRoot, "", 0, dtm) {
//    init {
//        add(Undefined2DataType(), "prout", null)
//    }
//    class Value(val dt: Thing)
// //    data class ()
// }
//
// abstract class StructDescriptor<T : Any>(val name: String, val desc: String, val default: T) :
//    PropertyDelegateProvider<StructDescriptor.Structable, StructDescriptor<T>.Holder> {
// //    abstract fun get(options: Options): T
// //    abstract fun set(options: Options, value: T)
// //    abstract fun read(option: Option): T
// //    open fun register(options: Options) = options.registerOption(
// //        name,
// //        default,
// //        null,
// //        desc,
// //    )
//
//    inner class Holder {
// //        private var value = default
// //        fun get() = value.asOption()
// //        fun set(edited: Option) {
// //            value = read(edited)
// //        }
// //        fun read(options: Options) {
// //            value = options[option]
// //        }
// //        fun write(options: Options) {
// //            options[option] = value
// //        }
//
//        val option get() = this@StructDescriptor
//        operator fun getValue(thisRef: Structable, property: KProperty<*>) =
//    thisRef.dt.components?.firstOrNull { it.fieldName == name }?.ordinal?.let(this::get)
// //        operator fun setValue(thisRef: Any?, property: KProperty<*>, new: T) {
// //            value = new
// //        }
//    }
//
// //    interface Container {
// //        fun <T : Any> bind(option: OptionDescriptor<T>): OptionDescriptor<T>.Holder
// //    }
//
// interface Structable {
//    val dt: StructureDataType
// //    val data: Data
// }
//
//    /**
//     * This option carrying [this], in the form an exporter hands the dialog. Per subclass rather
//     * than one untyped default: since 12.2 an [Option] is built as the subclass matching its value
//     * type, and there is none for an arbitrary value.
//     */
// //    abstract fun T.asOption(): Option
//    override operator fun provideDelegate(thisRef: Structable, property: KProperty<*>) = thisRef.bind(this)
// }

/**
 * A vtable record, located: where it starts, the [header] laid there, and the [abi] that laid it out. An
 * Itanium record's header is a [vtableHeaderLayout], read back through it ([readHeader]), and its function
 * array starts right after it. A gcc 2.x record has none: its reserved entry belongs to the vftable struct,
 * and its `{vfptr}` holds the record start rather than the address point. Built by [vtableRecord].
 */
data class VtableRecord(val address: Address, val header: StructureDataType?, val abi: CxxAbi) {
    /** Where the function array starts: past the header, or past gcc 2.x's reserved entry. */
    val addressPoint: Address get() = address.add(header?.length?.toLong() ?: abi.headerBytes(address.pointerSize))

    /** The vbase/vcall-offset words in front of `offset_to_top` and the rtti pointer. */
    val prefixWords get() = header?.let { it.numComponents - 2 } ?: 0

    /** What a `{vfptr}` pointing into this record holds, where the `vftable` label goes. */
    val vptrTarget get() = if (header == null) address else addressPoint

    /** Where [header]'s field [name] sits in memory. */
    fun fieldAddress(name: String): Address? = header?.field(name)?.let { address.add(it.offset.toLong()) }

    private fun StructureDataType.field(name: String) = components.firstOrNull { it.fieldName == name }

    /** [header] as memory holds it, read through its layout; null for a gcc 2.x record. */
    fun readHeader(program: Program): Data? = header?.let { program.readAt(address, it) }

    /**
     * The vbase offset `this` keeps for virtual [base]: where [base] sits in the class `this` is the
     * primary vtable of. [base]'s offset is that word's position behind the address point, which the typeinfo
     * gives exactly, so the word is commented with [base]'s name over [prefixKind]'s guess. Null when that
     * word is not one of the header's offset words.
     */
    fun vbaseOffset(program: Program, base: Rtti.Reader.Base) = vtableOffsetField(
        ((addressPoint + base.offset - address) / program.defaultPointerSize).toInt(),
    ).let { field ->
        fieldAddress(field)?.let { program.listing.setComment(it, CommentType.EOL, "vbase offset: ${base.className}") }
        readHeader(program)?.getScalar(field)?.signedValue
    }

    /** The typeinfo the rtti word points at. */
    fun rttiOf(program: Program): Address? = readHeader(program)?.valueOf<Address>(Itanium.RTTI)

    /**
     * What prefix word [i] of [total] is, given the class's [virtualBases]. The ABI orders the words
     * before `offset_to_top` as vcall offsets then vbase offsets (§2.5.2), one vbase offset per virtual
     * base — so knowing how many virtual bases the stab declares splits the run from the right-hand end,
     * and names each vbase word. A vbase offset of 0 is normal, not a gap: an empty abstract base sits at
     * offset 0 (CryptoPP's interface lattice gives eleven vtables twelve zeroed vbase offsets).
     *
     * Falls back to the undifferentiated label when the stab declares no virtual base — either the class
     * genuinely has none and this is a swept class we know nothing about, or the count disagrees, which
     * [ghistabs.importer.ClassApplier] reports separately.
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

    /** Whether a vtable group's own symbol sits on any word of [header]: the walk is past its group. */
    fun opensGroup(program: Program): Boolean =
        generateSequence(address) { it.add(program.defaultPointerSize.toLong()) }
            .takeWhile { it < addressPoint }
            .any { at -> program.symbolTable.getSymbols(at).any { startsVtableGroup(it.name) } }

    /**
     * Addresses the function-pointer array at [addressPoint], in slot order. Nothing records its
     * length, so it ends where the entries stop pointing into executable memory — at the next record's
     * `offset_to_top` (0) or rtti pointer (into .data). Walks by the record's ABI's entry stride and reads `pfn` at
     * its offset within the entry, which is what separates a gcc 2.x table without thunks from one with.
     */
    fun vtableSlotTargets(program: Program): List<Address> =
        generateSequence(addressPoint) { it.add(abi.stride(program.defaultPointerSize)) }
            .map { program.codeTargetAt(it.add(abi.pfnOffset(program.defaultPointerSize))) }
            .takeWhile { it != null }
            .filterNotNull()
            .toList()

    /**
     * The `rtti:` header comment, reporting the typeinfo symbol that is actually there. [Itanium.zti]
     * builds a closed-form name, and for anything the shorthand or a template spells differently that
     * name does not exist: `std::istream`'s record is `_ZTISi`, not `_ZTIN3std7istreamE`. Prefers the
     * linkage name over Ghidra's own demangled label, which is also a symbol at that address and would
     * render as "rtti: typeinfo typeinfo".
     */
    private fun rttiComment(program: Program, className: String): String {
        val name = rttiOf(program)
            ?.let { program.symbolTable.getSymbols(it).map { s -> s.name } }
            ?.let { names -> names.firstOrNull(Itanium::looksLikeZti) ?: names.firstOrNull() }
            ?: Itanium.zti(className)
        return "${Itanium.RTTI}: $name typeinfo"
    }

    /**
     * Lay this record, and return the address its `{vfptr}` holds — where the [vftable] struct, if any, and its
     * label go, so a constructor's `this->vfptr = &<Class>::vftable` resolves to a symbol and a
     * virtual call resolves to one of its fields. The labels are Ghidra's ([ClassNaming]): `internal_` on a
     * secondary, `construction-` in a construction group (`_ZTC`), and the vftable's `vftable_for_<[base]>`
     * once its class has several ([ClassNaming.vftableLabel]); the header's label never takes a base.
     *
     * Itanium points at the address point, and the record's header is laid in front of it as its
     * [vtableHeaderLayout], resolved through [registry]; the rtti pointee stays an untyped `void*` until
     * backlog §24 wires it. Each header word also gets an EOL comment saying what it holds for this class,
     * which the shared layout cannot. gcc 2.x points at the record start, so its reserved header is *inside*
     * the struct — laid as fields by the caller rather than here, because a header struct there would
     * collide with the vftable covering the same bytes.
     */
    fun lay(
        registry: DtmRegistry,
        program: Program,
        vftable: Structure?,
        className: String,
        ns: Namespace,
        virtualBases: List<String> = emptyList(),
        internal: Boolean = false,
        source: SourceType = SourceType.IMPORTED,
        construction: Boolean = false,
        base: String? = null,
    ): Address {
        val vftableLabel = ClassNaming.vftableLabel(internal, construction, base)
        // gcc 2.x labels the record start, because that is what a `{vfptr}` holds. The struct is *not*
        // stamped over the bytes: gcc declares the record itself (`__vtbl_ptr_type __vt_9TiXmlNode[20]`),
        // which is authoritative on length in a way nothing here is, and a virtual call resolves off the
        // vfptr's pointee type rather than off whatever data is applied at the target.
        if (header == null) {
            program.listing.setComment(address, CommentType.EOL, "gcc 2.x vtable: reserved entry, then the slots")
            program.labelVtable(address, vftableLabel, ns, source)
            return address
        }

        program.labelVtable(address, ClassNaming.vtableLabel(internal, construction), ns, source)
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

/** The Itanium record at [start] whose rtti word sits at [rttiSlot], or the canonical 2-word one if null. */
private fun Program.recordAt(start: Address, rttiSlot: Address?, abi: CxxAbi): VtableRecord {
    val ptr = defaultPointerSize.toLong()
    val prefixWords = rttiSlot?.let { ((it - start) / ptr - 1).toInt() } ?: 0
    val header = vtableHeaderLayout(dataTypeManager, prefixWords)
    return VtableRecord(start, header, abi)
}

/**
 * Locate the fixed words of the record at [ztv]. The address point is *not* a fixed `ztv + 2*ptrSize`:
 * a class with a virtual base anywhere in its hierarchy (anything derived from an iostream —
 * `basic_istream` virtually inherits `basic_ios`) has vbase/vcall-offset words before offset_to_top,
 * so `_ZTV<class>` points that many words early. Find the rtti header instead — the one word holding
 * the address of a `_ZTI…` symbol — and read the other two off it. Falls back to the canonical
 * 2-word header when no such word is in reach (templates, stripped rtti).
 *
 * The search stops at the first word that points into code, which is this record's own function
 * array: reaching it means the record has no rtti header, and without that stop the scan would run
 * on into the *next* record and adopt its rtti — laying offset_to_top, the address point and a run
 * of "vbase offset" comments inside the wrong object. `MAX_VTABLE_PREFIX_WORDS` alone never bounded
 * that, it only capped how far the damage spread.
 *
 * A gcc 2.x record has no typeinfo pointer to search for ([CxxAbi.hasRttiHeader]) and no
 * vbase/vcall prefix either, so it gets no header layout, and its address point is past the reserved
 * entry.
 */
fun Program.vtableRecord(ztv: Address, abi: CxxAbi = Itanium): VtableRecord {
    if (!abi.hasRttiHeader) return VtableRecord(ztv, null, abi)
    val ptr = defaultPointerSize.toLong()
    fun holdsTypeinfo(slot: Address) =
        readPointer(slot)?.let { pointee -> symbolTable.getSymbols(pointee).any { it.isTypeinfo } } == true

    val rttiSlot = generateSequence(ztv) { it.add(ptr) }
        .take(MAX_VTABLE_PREFIX_WORDS)
        .takeWhile { holdsTypeinfo(it) || codeTargetAt(it) == null }
        .firstOrNull(::holdsTypeinfo)
    return recordAt(ztv, rttiSlot, abi)
}

/** A record of a `_ZTV` group: where its fixed words sit, and the function pointers it holds. */
data class SubVtable(val record: VtableRecord, val targets: List<Address>) {
    fun endOfSlots(ptrSize: Int): Address = record.addressPoint.add(targets.size.toLong() * ptrSize)
}

/**
 * The sub-vtable beginning at [start], or null if what is there does not belong to [rtti]'s group. One
 * with no slots is still a record: a base with no virtuals of its own keeps its vptr and header
 * (`Right` in `Diamond`, ahead of `Named`'s), and stopping at it would lose every record after it.
 */
private fun Program.subVtableAt(start: Address, rtti: Address): SubVtable? =
    generateSequence(start) { it.add(defaultPointerSize.toLong()) }
        .take(MAX_VTABLE_PREFIX_WORDS)
        .takeWhile { readPointer(it) == rtti || codeTargetAt(it) == null }
        // offset_to_top precedes rtti, so a match on the first word would put the top slot back
        // inside the primary's function array.
        .firstOrNull { it > start && readPointer(it) == rtti }
        ?.let { recordAt(start, it, Itanium) }
        ?.let { record -> SubVtable(record, record.vtableSlotTargets(this)) }

/**
 * The secondary sub-vtables following the primary record, whose slots end at [afterPrimary] — one per
 * virtual base, each its own `[vcall offsets…] offset_to_top rtti [thunks]` (ABI §2.5.2), none bearing
 * a symbol. Nothing delimits the group, so the walk is bounded by the one invariant that does: every
 * record in it describes the same complete object, hence carries the same [rtti] pointer. That alone
 * runs on into the next group when it shares the rtti: a construction vtable's names the base, and
 * CryptoPP lays `GeneratableCryptoMaterial`'s `-in-` groups for three classes back to back. So the walk
 * also stops at a record whose header holds the next group's own symbol.
 */
fun Program.secondaryVtables(afterPrimary: Address, rtti: Address): List<SubVtable> =
    generateSequence(subVtableAt(afterPrimary, rtti)) {
        subVtableAt(it.endOfSlots(defaultPointerSize), rtti)
    }.takeWhile { sub -> !sub.record.opensGroup(this) }.toList()

/**
 * `createLabel` hands back a label already there as it stands, so a class laying a table an earlier
 * sweep labelled has to raise the label's source itself: that source is what [isVtableClaimed] reads.
 */
private fun Program.labelVtable(at: Address, label: String, ns: Namespace, source: SourceType) {
    val sym = symbolTable.createLabel(at, label, ns, source)
    if (source == SourceType.IMPORTED && sym.source != source) sym.source = source
}

/**
 * Rename [ns]'s [from] label at [at] to [to], as `RTTIGccClassRecoverer` renames a class's tables once it
 * has several. A [to] already there (an earlier import's) takes the place of [from] instead.
 */
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
 * Whether [label], one of a class's vftable labels ([ClassNaming.isClassVftableLabel]), marks its primary
 * table. Once a class has several they are all `vftable_for_<Base>`, so that is read off the record: an
 * Itanium primary's header is labelled `vtable` rather than `internal_vtable`, and a gcc 2.x one sits at
 * the class's own `_vt` symbol rather than at a `_vt<class><base>` one.
 */
fun Program.isPrimaryVftable(label: Symbol): Boolean = when (label.name) {
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
 * The struct of the class table [label] marks: laid there under Itanium, and found by name under gcc 2.x,
 * which lays none over its record. A `vftable_for_<Base>` label is struct `<leaf>_vftable_for_<Base>`,
 * and a primary still labelled `vftable` is `<leaf>_vftable` alone or `<leaf>_vftable0` among several.
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
 * Whether a class that describes [record] already laid it: [VtableRecord.lay] with
 * [SourceType.IMPORTED] left one of its own vftable labels ([ClassNaming.isClassVftableLabel]) where
 * its `{vfptr}` points. This
 * is how a sweep tells what is left without the class pass's own bookkeeping. A swept table is
 * labelled [SourceType.ANALYSIS], so a later sweep lays it again rather than skipping it.
 */
fun Program.isVtableClaimed(record: VtableRecord): Boolean = symbolTable.getSymbols(record.vptrTarget)
    .any { it.source == SourceType.IMPORTED && ClassNaming.isClassVftableLabel(it.name) }

/** Where a class's vtable record sits, and which ABI lays it out past the header. */
data class ResolvedVtable(val className: String, val address: Address, val abi: CxxAbi) {
    companion object {
        /** For a caller that already knows the class and is only checking a spelling of it. */
        fun of(className: String, symName: String, addr: Address) =
            CxxAbi.ofVtableSymbol(symName)?.let { ResolvedVtable(className, addr, it) }

        /**
         * For a caller holding only the symbol, which has to demangle to learn the class. gcc 2.x
         * needs the primary screen on top of [CxxAbi.ofVtableSymbol]: a second cplus-marker separates a base,
         * naming that base's secondary table rather than the class's own.
         */
        fun fromSymbol(sym: Symbol) = CxxAbi.ofVtableSymbol(sym.name)
            ?.takeIf { it.isPrimaryVtable(sym.name) }
            ?.let { abi ->
                Demangler.of(sym.name)
                    ?.let(abi::demangledVtableClass)
                    ?.let { ResolvedVtable(it, sym.address, abi) }
            }
    }
}
