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
 * Places the virtual bases a class struct lacks where its Itanium vtable says they are: the typeinfo
 * gives the vtable word, which gives the offset. A base nothing defines is built off its typeinfo, a vptr
 * then the first base of it something defines; where that doesn't fit, that part alone is placed.
 *
 * A class's struct is found by the namespace of its demangled labels, else by the stabs import's class
 * record ([readClassRecord]). Anything already there, or that would not fit, is left and reported.
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
        // Placed already, by the stabs or an earlier run.
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
     * A struct for [vbase], which nothing defines: its vptr, then the [part] something defines [within]
     * bytes in, sized to the [room] the class leaves it. It fills an empty placeholder where one stands.
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
        // A nearly-empty virtual base can be the primary one, sharing the class's vptr: nothing to place.
        0 -> false.also { debug("vbase-primary-from-vtable") }

        in 1..<length -> true

        // Right past the end: this struct is only a base subobject; the deriving class places the virtual base.
        length -> false.also { debug("vbase-past-base-subobject", at) }

        else -> false.also {
            degradation("vbase-offset-unreadable", at, "vtable word at ${vbase.offset} reads $vbaseAt")
        }
    }

    private fun Structure.takeAcceptable() = takeUnless { it.isZeroLength }

    /** The bytes from [offset] to the next defined component or the end. */
    private fun Structure.roomAt(offset: Int) =
        (definedComponents.map { it.offset }.filter { it > offset }.minOrNull() ?: length) - offset

    /** [className]'s non-empty struct, by [lookup]. */
    private fun structFor(className: String, namespace: Namespace?) =
        lookup(className, namespace).firstNotNullOfOrNull { it.takeAcceptable() }

    /** What may be [className]'s struct, empty or not: by [namespace], then as [recorded]. */
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

    /** [base]'s struct, else the first defined one down its first non-virtual bases, with its offset in [base]. */
    private fun definedPart(base: Rtti.Reader.Base, depth: Int = 0): Pair<DataType, Int>? =
        structFor(base.className, namespaceOfTypeinfo(base.typeinfo))?.let { it to 0 }
            ?: base.typeinfo.takeIf { depth < Rtti.MAX_BASE_DEPTH }?.let(reader::basesOf)
                ?.filterNot { it.isVirtual }?.minByOrNull { it.offset }
                ?.let { next -> definedPart(next, depth + 1)?.let { (dt, at) -> dt to at + next.offset.toInt() } }
}
