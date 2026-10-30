package ghistabs.cpp.abi.itanium

import ghidra.program.database.data.DataTypeUtilities
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghistabs.componentsOverlapping
import ghistabs.cpp.*
import ghistabs.cpp.ClassHierarchyRecords.Companion.readClassRecord
import ghistabs.cpp.abi.VtableRecord
import ghistabs.cpp.abi.vtableRecord
import ghistabs.diagnose.DiagnosticSink

/**
 * Places the virtual bases a class struct lacks, where its Itanium vtable says they are. A class deriving
 * from `basic_ifstream<char>` that no debug info defines has no virtual base in its struct; its typeinfo
 * still says `basic_istream` has `basic_ios` as a virtual base whose offset is 12 bytes behind the
 * vtable's address point, and the class's `_ZTV` holds that offset there. When nothing defines
 * `basic_ios` either, it is built off its typeinfo: its own vptr, then the first base of it that something
 * defines where the typeinfo puts it, `ios_base` 4 bytes in. Where that does not fit, that base alone is laid.
 *
 * Needs the labels demangled, so each `vtable` and `typeinfo` sits in its class's namespace, which
 * [DataTypeUtilities.findExistingClassStruct] finds the class's struct by. Where that finds none (a struct
 * renamed by typedef shortening, or filed under a CU's category), the struct a stabs import recorded for
 * the class ([readClassRecord]) answers, by that namespace or the class's qualified name. gcc 2.x fills
 * its typeinfo at run time, so has none to read. A struct already holding something where a virtual base
 * goes is taken to have it, and anything that would not fit, or would cover laid bytes, is reported and left.
 */
class VirtualBases(private val program: Program, sink: DiagnosticSink) : DiagnosticSink by sink {
    private val dtm = program.dataTypeManager
    private val reader = Rtti.Reader(program)
    private val record = program.readClassRecord().orEmpty()

    /** [record] by qualified class name, for a label the demangler left outside its class's namespace. */
    private val recordByName by lazy {
        record.mapNotNull { (id, entry) -> program.symbolTable.getSymbol(id)?.getName(true)?.let { it to entry } }
            .toMap()
    }

    /** Lays every class's; returns how many virtual bases it laid. */
    fun placeAll(): Int = program.symbolTable.getSymbols(ClassNaming.VTABLE).iterator().asSequence()
        .distinctBy { it.address }
        .sumOf { sym ->
            val struct = sym.vtableClass?.let { structFor(it, sym.parentNamespace) } ?: return@sumOf 0
            val record = runCatching { program.vtableRecord(sym.address) }.getOrNull() ?: return@sumOf 0
            val vbases = record.rttiOf(program)?.let(reader::virtualBasesOf).orEmpty()
            val count = struct.definedComponents.count { it.isBaseField() } + vbases.size
            vbases.count { struct.place(it, record, count) }
        }

    private fun Structure.place(vbase: Rtti.Reader.Base, record: VtableRecord, count: Int): Boolean {
        val at = pathName.member(vbase.className)
        val vbaseAt = record.vbaseOffset(program, vbase)?.toInt()
            .takeIf { isInside(it, vbase, at) } ?: return false

        val (found, foundWithin) = definedPart(vbase) ?: return false.also {
            degradation("vbase-undefined", at, "nothing defines it or a base of it")
        }
        // Laid already, by the class layout off the stab's own inheritance line, or by an earlier run.
        getComponentAt(vbaseAt)?.takeIf { it.offset == vbaseAt }?.dataType?.name?.let { laid ->
            if (laid == vbase.className.leafName || laid == found.name) return false
        }
        val (dt, within) = synthesized(vbase, found, foundWithin, roomAt(vbaseAt), at)?.let { it to 0 }
            ?: (found to foundWithin)

        val offset = vbaseAt + within
        when {
            offset + dt.length > length -> "${dt.name} (${dt.length}b) at +$offset overruns $length"
            componentsOverlapping(offset, dt.length).isNotEmpty() -> "${dt.name} at +$offset covers laid fields"
            else -> null
        }?.let { problem -> return false.also { degradation("vbase-layout-failed", at, problem) } }

        val part = "; only its ${dt.name} at +$within is defined"
            .takeUnless { within == 0 && dt.name == vbase.className.leafName }.orEmpty()
        placeBase(
            this,
            offset,
            dt,
            isVirtual = true,
            "${vbase.access.name.lowercase()} virtual ${vbase.className} at " +
                "+0x${vbaseAt.toString(16)}, by the vtable$part",
            ClassNaming.baseFieldName(true, dt.name, count),
            at,
        )
        return true
    }

    /**
     * Undefined [vbase] as its own struct, built off its typeinfo once the first class to need it does: its
     * vptr at 0, typed after its own vftable when one is laid (a dynamic class with no base at 0 allocates
     * one, Itanium ABI §2.4), then the [part] something defines [within] bytes in. Nothing says how long it
     * is, so it takes the [room] the class leaves it. Filled into the empty placeholder already standing for
     * it (a stab's forward declaration), else added where its labels' namespace files it.
     */
    private fun synthesized(vbase: Rtti.Reader.Base, part: DataType, within: Int, room: Int, at: String): Structure? {
        val ptr = program.defaultPointerSize
        val ns = namespaceOfTypeinfo(vbase.typeinfo)?.takeUnless { it.isGlobal }
        if (ns == null || within < ptr || within + part.length > room) return null
        val vftable = dtm.getDataType(ClassNaming.vftablePath(ns))
        val category = ns.parentNamespace.getPathList(true)
            .fold(CategoryPath.ROOT) { path, seg -> CategoryPath(path, seg) }
        val placeholder = lookup(vbase.className, ns).firstOrNull { it.isZeroLength }
        val struct = (placeholder ?: StructureDataType(category, ns.name, 0, dtm)).apply {
            growStructure(room)
            replaceAtOffset(0, PointerDataType(vftable, ptr, dtm), ptr, ClassUtils.VFPTR, "vtable pointer")
            replaceAtOffset(within, part, part.length, ClassNaming.baseFieldName(false, part.name, 1), "public base")
            description = "Defined nowhere: built off its typeinfo, its size guessed from the $room bytes $at leaves it"
        }
        degradation("vbase-size-guessed", at, "$room bytes from the deriving class")
        return struct.takeIf(dtm::contains) ?: dtm.resolve(
            struct,
            DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER,
        ) as? Structure
    }

    /** Whether [vbaseAt] puts [vbase] inside [this], logging why not where it doesn't. */
    private fun Structure.isInside(vbaseAt: Int?, vbase: Rtti.Reader.Base, at: String): Boolean = when (vbaseAt) {
        // A nearly-empty virtual base can be the primary base, sharing the class's vptr at 0 (CryptoPP's
        // CryptoMaterial under CryptoParameters): there is nothing of its own to lay.
        0 -> false.also { debug("vbase-primary-from-vtable") }

        in 1..<length -> true

        // Right past the struct's end: it holds only the non-virtual part, as a forward-declared base
        // sized off the gap its deriving class leaves does, and the offset agrees with that guess. The
        // deriving class, whose object the virtual base is part of, places it there.
        length -> false.also { debug("vbase-past-base-subobject", at) }

        else -> false.also {
            degradation("vbase-offset-unreadable", at, "vtable word at ${vbase.offset} reads $vbaseAt")
        }
    }

    private fun Structure.takeAcceptable() = takeUnless { it.isZeroLength }

    /** The bytes from [offset] to the next laid component, or the end of [struct]. */
    private fun Structure.roomAt(offset: Int) =
        (definedComponents.map { it.offset }.filter { it > offset }.minOrNull() ?: length) - offset

    /** [className]'s struct, by the namespace its demangled labels sit in, else as [recorded]. */
    private fun structFor(className: String, namespace: Namespace?) =
        lookup(className, namespace).firstNotNullOfOrNull { it.takeAcceptable() }

    /** What may be [className]'s struct, empty or not: by the namespace, then as [recorded]. */
    private fun lookup(className: String, namespace: Namespace?) = listOfNotNull(
        when (namespace) {
            is GhidraClass -> DataTypeUtilities.findExistingClassStruct(dtm, namespace)

            else if namespace?.isGlobal == false -> DataTypeUtilities.findDataType(
                dtm,
                namespace.parentNamespace,
                namespace.name,
                Structure::class.java,
            )

            else -> null
        },
        recorded(className, namespace),
    )

    /** The struct a stabs import recorded for [className]: by its [namespace], else by its qualified name. */
    private fun recorded(className: String, namespace: Namespace?): Structure? {
        val entry = (namespace as? GhidraClass)?.let { record[it.id] } ?: recordByName[className]
        return entry?.structId?.let(dtm::getDataType) as? Structure
    }

    /** The namespace the demangled `typeinfo` label at [zti] sits in. */
    private fun namespaceOfTypeinfo(zti: Address) = program.symbolTable.getSymbols(zti)
        .firstOrNull { it.name == ClassNaming.TYPEINFO && it.typeinfoClass != null }?.parentNamespace

    /**
     * [base]'s struct, else the first one down its chain of first non-virtual bases, with where that sits
     * in [base]: `basic_ios` keeps its own vptr in front of `ios_base`, at +4.
     */
    private fun definedPart(base: Rtti.Reader.Base, depth: Int = 0): Pair<DataType, Int>? =
        structFor(base.className, namespaceOfTypeinfo(base.typeinfo))?.let { it to 0 }
            ?: base.typeinfo.takeIf { depth < Rtti.MAX_BASE_DEPTH }?.let(reader::basesOf)
                ?.filterNot { it.isVirtual }?.minByOrNull { it.offset }
                ?.let { next -> definedPart(next, depth + 1)?.let { (dt, at) -> dt to at + next.offset.toInt() } }
}
