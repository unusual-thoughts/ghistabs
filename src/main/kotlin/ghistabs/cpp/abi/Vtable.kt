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

/** How an ABI spells a vtable's symbol, and which class one names. */
interface VtableSymbols {
    /** Does [symbolName] look like a vtable symbol of this ABI? */
    fun looksLikeVtable(symbolName: String): Boolean

    /**
     * Does [symbolName] name a class's *own* table, rather than a base's secondary? Itanium packs a
     * class's secondaries into the primary record, so every `_ZTV` is one and the default holds;
     * gcc 2.x gives each secondary its own symbol, which only the mangled spelling distinguishes.
     */
    fun isPrimaryVtable(symbolName: String) = looksLikeVtable(symbolName)

    /** Closed-form vtable symbol spellings for [className], most canonical first. */
    fun vtableCandidates(className: String): List<String>

    /** Qualified class name [obj] names, if it is this ABI's demangled vtable object. */
    fun demangledVtableClass(obj: DemangledObject): String?
}

/**
 * How an ABI lays out a vtable record. By default the Itanium and MSVC shape: a header before the address
 * point the vptr holds, then one pointer per slot.
 */
interface VtableLayout {
    /**
     * Where a primary vptr sits in its object, where the ABI fixes that: at 0 under Itanium and MSVC. Null
     * under gcc 2.x, which puts it after the fields, where only the class struct can say.
     */
    val primaryVptrOffset: Long? get() = 0L

    /** The record at [at], a class's vtable symbol. */
    fun recordAt(program: Program, at: Address): VtableRecord

    /**
     * [record]'s address point, which is what a `{vfptr}` pointing into it holds, where its `vftable` label
     * goes and where the `_vftable` struct begins: by default right past the header laid there.
     */
    fun addressPoint(record: VtableRecord): Address = record.address.add(record.header?.length?.toLong() ?: 0L)

    /** Where each slot's function pointer sits, in slot order, in bytes from the address point. */
    fun slotOffsets(ptrSize: Int): Sequence<Long> = generateSequence(0L) { it + ptrSize }

    /**
     * Entries the header occupies in a stab's slot numbering (`*<n>`): none where the vptr already
     * points past it, as Itanium's does.
     */
    fun reservedEntries(ptrSize: Int) = 0

    /**
     * The reserved entry gcc 2.x puts at the front of a record, as struct fields — the `{vfptr}`
     * points here, so the slots only land on their real byte offsets if the header occupies its own.
     * `cp/class.c:skip_rtti_stuff` reserves two pointer-wide entries with thunks and one 8-byte
     * `{delta, index, pfn}` without; 8 bytes either way on 32-bit. Nothing here is a Pointer, which
     * is what keeps the header out of the slot list everything else counts.
     */
    fun Structure.addReservedHeader() = Unit

    /**
     * The `{delta, index}` half of a gcc 2.x no-thunk entry, which precedes its `pfn` and is what
     * makes the entry 8 bytes wide. `delta` is live at every call site — the dispatch reads it with
     * `movswl` and adds it to `this` before the call — so it is a signed short and worth naming.
     */
    fun Structure.addEntryAdjustment(slot: Int) = Unit

    /**
     * Where the `{vfptr}` holding this record's address point sits in the complete object, as far as
     * the record itself says: Itanium's `offset_to_top`, negated — 0 for a primary, the subobject's
     * offset for a secondary. A gcc 2.x record states no such word; its tables are placed by the
     * symbol that names them and the class struct.
     */
    fun VtableRecord.vfptrOffset(program: Program): Long? = null
}

/**
 * A vtable record, located: where it starts, the [header] laid there, and the [abi] that laid it out. An
 * Itanium record's header is a [vtableHeaderLayout], read back through it ([readHeader]), and its function
 * array starts right after it. A gcc 2.x record has none: its reserved entry belongs to the vftable struct,
 * and its `{vfptr}` holds the record start, which is its address point, rather than where the slots start.
 * Built by [vtableRecord].
 */
data class VtableRecord(val address: Address, val header: StructureDataType?, val abi: CxxAbi) {
    /** The vbase/vcall-offset words in front of `offset_to_top` and the rtti pointer. */
    val prefixWords get() = header?.let { it.numComponents - 2 } ?: 0

    /** What a `{vfptr}` pointing into this record holds, where the `vftable` label goes. */
    val addressPoint: Address get() = abi.addressPoint(this)

    /** Where [header]'s field [name] sits in memory. */
    fun fieldAddress(name: String): Address? = header?.field(name)?.let { address.add(it.offset.toLong()) }

    private fun StructureDataType.field(name: String) = components.firstOrNull { it.fieldName == name }

    /** [header] as memory holds it, read through its layout; null for a gcc 2.x record. */
    fun readHeader(program: Program): Data? = header?.let { program.dataAt(address, it) }

    /**
     * The vbase offset `this` keeps for virtual [base]: where [base] sits in the class `this` is the
     * primary vtable of. [base]'s offset is that word's position behind the address point, which the typeinfo
     * gives exactly, so the word is commented with [base]'s name over [prefixKind]'s guess. Null when that
     * word is not one of the header's offset words.
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
     * Addresses the function-pointer array off [addressPoint], in slot order. Nothing records its
     * length, so it ends where the entries stop pointing at functions — at the next record's
     * `offset_to_top` or rtti pointer (into .data). A function is one in executable memory, or an import
     * the loader's EXTERNAL block stands in for: an abstract class's slots in a dynamic link hold
     * `__cxa_pure_virtual`'s. Up to two nulls are slots when a function follows them, else the next record's
     * `offset_to_top`: gcc 12 leaves 0 in an abstract class's destructor slots (`tinyxml2::MemPool`'s
     * `{0, 0, __cxa_pure_virtual…}`). Walks by the record's ABI's entry stride and reads `pfn` at
     * its offset within the entry, which is what separates a gcc 2.x table without thunks from one with.
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
     * Whether [pfn] is relocated against the import whose thunk sits at [target]. The loader packs data
     * imports in the same EXTERNAL block, so a thunk at [target] alone is not enough: a typeinfo's vptr
     * (`_ZTVN10__cxxabiv120__si_class_type_infoE+0x10`) can land on some function's.
     */
    private fun Program.isImportedFunction(pfn: Address, target: Address): Boolean {
        val thunk = functionManager.getFunctionAt(target)?.takeIf { it.isThunk } ?: return false
        return relocationTable.getRelocations(pfn).any { it.symbolName == thunk.name }
    }

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
        return "$name typeinfo"
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

/** gcc's two destructor entries, complete and deleting: the only slots it leaves null. */
private const val DESTRUCTOR_SLOTS = 2

/**
 * The record at [ztv], the address of a class's vtable symbol, as [abi] finds it ([VtableLayout.recordAt]).
 */
fun Program.vtableRecord(ztv: Address, abi: CxxAbi = Itanium): VtableRecord = abi.recordAt(this, ztv)

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
 * the class's own `_vt` symbol rather than at a `_vt<class><base>` one. MSVC labels every table of a class
 * `vftable`, and its complete object locator says which subobject it serves ([msvcSubobjectOffset]).
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
fun Program.isVtableClaimed(record: VtableRecord): Boolean = symbolTable.getSymbols(record.addressPoint)
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
