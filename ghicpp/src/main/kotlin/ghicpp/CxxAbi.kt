package ghicpp

import ghidra.app.util.demangler.DemangledObject
import ghidra.program.model.address.Address
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.Symbol
import ghidra.util.task.TaskMonitor
import ghidrakt.*

/** How a C++ ABI spells a member's symbol, which is asked before any vtable has said which ABI it is. */
interface CxxMemberNaming {
    /** Whether this ABI mangled [name], as opposed to a C symbol or a compiler label. */
    fun isProbablyMangled(name: String): Boolean

    /** The symbols [m] may have been emitted as, the stated physname first. */
    fun physnameCandidates(m: MemberDecl, className: String): List<String> = listOfNotNull(m.mangled)

    /** How this ABI's stabs spell the implicit assignment operator. */
    val assignmentOperatorName: String get() = "operator="

    /** Whether [physname] is itself the symbol of an implicit special member. */
    fun physnameIsImplicit(physname: String) = false

    /**
     * A constructor, destructor or assignment operator the compiler emits only when used. gcc declares
     * them for every aggregate, C structs included, so a missing symbol is expected. Told by name, or by a
     * physname that is itself such a symbol ([physnameIsImplicit]).
     */
    fun isImplicitMember(m: MemberDecl, className: String): Boolean {
        val leaf = className.templateLeaf
        return m.name == leaf || m.name == "~$leaf" || m.name == assignmentOperatorName ||
            m.mangled?.let(::physnameIsImplicit) == true
    }

    /** The constructor or destructor [mangled] names, given [className] where the mangling needs it; else null. */
    fun structorOf(mangled: String, className: String? = null): Structor?

    /** A member the compiler may have inlined away, so a missing function is no failure. */
    fun isInlineStdMember(name: String) = false
}

/**
 * A C++ ABI: how it names members ([CxxMemberNaming]), lays out vtables ([VtableLayout]) and spells
 * them ([VtableSymbols]), and builds and destroys objects ([StructorConvention]).
 */
interface CxxAbi :
    CxxMemberNaming,
    VtableLayout,
    VtableSymbols,
    StructorConvention {
    /**
     * [cls]'s direct bases from this ABI's own records: Itanium's typeinfo, MSVC's Base Class Array. Null
     * where there are none to read, as under gcc 2.x, which builds its typeinfo at run time.
     */
    fun basesOf(program: Program, cls: Namespace): List<BaseDecl>? = null

    /** The record that says where an object's virtual bases sit: Itanium's vtable, MSVC's vbtable. */
    val virtualBaseRecord: String get() = ClassNaming.VTABLE

    /**
     * Whether the table whose address point is [vftable] is one of this ABI's records, by the record's symbols.
     * By default a record starts at its address point, so its vtable symbol is there, as gcc 2.x's is.
     */
    fun ownsVftable(program: Program, vftable: Address): Boolean =
        program.symbolTable.getSymbols(vftable).any { looksLikeVtable(it.name) }

    /** Finds the ABI a symbol or table is of: its functions are in [ghicpp.abi], as `CxxAbi.ofVtableSymbol`. */
    companion object
}

/** A constructor or destructor variant, as its ABI names them: `ItaniumStructor`, `MsvcStructor`, `Gcc2Structor`. */
interface Structor {
    val isDestructor: Boolean

    /** Whether this destructor frees the object too, as the one a vftable slot holds does. */
    val isDeleting: Boolean

    /** How the class [className] spells this member in its own body: `Foo`, `~Foo`. */
    fun displayName(className: String): String
}

/** How an ABI's constructors and destructors behave, for `ThisFunctionDissector` and `AllocationSizeFinder`. */
interface StructorConvention {
    /** The variant [func] is, given its [role]; null where that doesn't say. */
    fun structorFor(role: StructorRole, func: Function): Structor? = null

    /** The names of a scalar `operator new(size)`, mangled and demangled. Not `new[]`'s, which adds a cookie. */
    val operatorNewNames: Set<String> get() = mangledOperatorNew + DEMANGLED_OPERATOR_NEW

    /** `operator new(size)` as this ABI mangles it, for each `size_t`. */
    val mangledOperatorNew: Set<String> get() = emptySet()

    /** The names of a scalar `operator delete`, which a deleting destructor frees `this` with. */
    val operatorDeleteNames: Set<String> get() = mangledOperatorDelete + DEMANGLED_OPERATOR_DELETE

    /** `operator delete(void *)`, and its sized form, as this ABI mangles them. */
    val mangledOperatorDelete: Set<String> get() = emptySet()

    private companion object {
        // Ghidra names an ELF's imported `operator delete` (`_ZdlPvj@CXXABI_1.3.9`) `operator.delete`.
        val DEMANGLED_OPERATOR_NEW = setOf("operator_new", "operator new", "operator.new")
        val DEMANGLED_OPERATOR_DELETE = setOf("operator_delete", "operator delete", "operator.delete")
    }
}

/** What a function storing vptrs does to its class, in any ABI; [StructorConvention.structorFor] gives the variant. */
enum class StructorRole { CONSTRUCTOR, DESTRUCTOR, DELETING_DESTRUCTOR }

/**
 * Reads an ABI's RTTI, from the labels, memory and structs other analyzers laid, and interprets it into the
 * classes the class pass recovers.
 */
interface RttiParser {
    /** The ABI whose RTTI this reads. */
    val abi: CxxAbi

    /** The classes the RTTI describes. */
    fun parse(monitor: TaskMonitor = TaskMonitor.DUMMY): ClassPassInput
}

/** How an ABI spells a vtable's symbol, and which class one names. */
interface VtableSymbols {
    /**
     * Whether [symbolName] is one of this ABI's symbols for a class's table of virtual functions, primary or
     * secondary. Where it sits is the ABI's: Itanium's `_ZTV` at the vtable's header, MSVC's `??_7` and gcc 2.x's
     * `_vt` at the vftable's address point.
     */
    fun looksLikeVtable(symbolName: String): Boolean

    /**
     * Whether [sym], one of this ABI's table symbols, is its class's own table rather than a base's secondary
     * one. By default every table symbol is, as Itanium's `_ZTV` names a whole vtable group. gcc 2.x and MSVC
     * give secondaries symbols of their own; MSVC qualifies all of a class's tables once it has several, its own
     * too, so its complete object locator must tell those apart.
     */
    fun isPrimaryTableSymbol(sym: Symbol): Boolean = looksLikeVtable(sym.name)

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
    fun vfptrOffsetOf(record: VtableRecord, program: Program): Long? = null

    /** Whether [name] is the runtime function this ABI points a pure virtual's slot at. */
    fun isPureVirtualStub(name: String): Boolean
}

/**
 * A vtable record ([CxxAbi.recordAt]): where it starts, the [header] in front of its address point, and its [abi].
 * Only Itanium's has a header ([ghicpp.abi.itanium.vtableHeaderLayout]). [internal] for a secondary,
 * [construction] for one in a `_ZTC` group, which its labels say as Ghidra's do ([ClassNaming.vftableLabel]).
 */
data class VtableRecord(
    val address: Address,
    val header: StructureDataType?,
    val abi: CxxAbi,
    val internal: Boolean = false,
    val construction: Boolean = false,
) {
    /** The vbase/vcall-offset words in front of `offset_to_top` and the rtti pointer. */
    val prefixWords get() = header?.let { it.numComponents - 2 } ?: 0

    /** What a vptr into this record holds, where its `vftable` label goes. */
    val addressPoint: Address get() = abi.addressPoint(this)

    /** Where the vptr into this record sits in the complete object, if the ABI knows ([VtableLayout.vfptrOffsetOf]). */
    fun vfptrOffset(program: Program): Long? = abi.vfptrOffsetOf(this, program)

    /** Where [header]'s field [name] sits in memory. */
    fun fieldAddress(name: String): Address? = header?.field(name)?.let { address.add(it.offset.toLong()) }

    private fun StructureDataType.field(name: String) = components.firstOrNull { it.fieldName == name }

    /** [header] as memory holds it, read through its layout; null for a gcc 2.x record. */
    fun readHeader(program: Program): Data? = header?.let { program.dataAt(address, it) }
}
