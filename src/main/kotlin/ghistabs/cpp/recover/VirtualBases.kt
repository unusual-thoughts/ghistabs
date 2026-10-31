package ghistabs.cpp.recover

import ghidra.program.database.data.DataTypeUtilities
import ghidra.program.model.data.*
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghistabs.componentsOverlapping
import ghistabs.cpp.*
import ghistabs.cpp.ClassHierarchyRecords.Companion.readClassRecord
import ghistabs.cpp.abi.CxxAbi
import ghistabs.diagnose.DiagnosticSink

/**
 * Places the virtual bases a class struct lacks where its [abi]'s records say they are
 * ([ClassDecl.virtualBases]). A base nothing defines is built off its RTTI, a vptr then the first base of
 * it something defines; where that doesn't fit, that part alone is placed.
 *
 * A class's struct is found by its namespace, else by the stabs import's class record ([readClassRecord]).
 * Anything already there, or that would not fit, is left and reported.
 */
class VirtualBases(private val program: Program, private val abi: CxxAbi, sink: DiagnosticSink) :
    DiagnosticSink by sink {
    private val dtm = program.dataTypeManager
    private val record = program.readClassRecord().orEmpty()

    /** [record] by qualified class name, for a class whose labels sit outside its class's namespace. */
    private val recordByName by lazy {
        record.mapNotNull { (id, entry) -> program.symbolTable.getSymbol(id)?.getName(true)?.let { it to entry } }
            .toMap()
    }

    /** Lays each of [classes]' virtual bases; returns how many it laid. */
    fun placeAll(classes: Collection<ClassDecl>): Int = classes.sumOf { cls ->
        val struct = structFor(cls) ?: return@sumOf 0
        val vbases = cls.virtualBases
        val count = struct.definedComponents.count { it.isBaseField() } + vbases.size
        vbases.count { struct.place(it, count) }
    }

    private fun Structure.place(vbase: ClassBase, count: Int): Boolean {
        val name = vbase.cls.qualifiedName
        val at = pathName.member(name)
        val vbaseAt = vbase.offset?.toInt().takeIf { isInside(it, at) } ?: return false

        val (found, foundWithin) = definedPart(vbase.cls) ?: return false.also {
            degradation("vbase-undefined", at, "nothing defines it or a base of it")
        }
        // Placed already, by the stabs or an earlier run.
        getComponentAt(vbaseAt)?.takeIf { it.offset == vbaseAt }?.dataType?.name?.let { laid ->
            if (laid == name.leafName || laid == found.name) return false
        }
        val (dt, within) = synthesized(vbase.cls, found, foundWithin, roomAt(vbaseAt), at)?.let { it to 0 }
            ?: (found to foundWithin)

        val offset = vbaseAt + within
        when {
            offset + dt.length > length -> "${dt.name} (${dt.length}b) at +$offset overruns $length"
            componentsOverlapping(offset, dt.length).isNotEmpty() -> "${dt.name} at +$offset covers laid fields"
            else -> null
        }?.let { problem -> return false.also { degradation("vbase-layout-failed", at, problem) } }

        val part = "; only its ${dt.name} at +$within is defined"
            .takeUnless { within == 0 && dt.name == name.leafName }.orEmpty()
        placeBase(
            this,
            offset,
            dt,
            isVirtual = true,
            "${vbase.access.name.lowercase()} virtual $name at +0x${vbaseAt.toString(
                16,
            )}, by the ${abi.virtualBaseRecord}$part",
            ClassNaming.baseFieldName(true, dt.name, count),
            at,
        )
        return true
    }

    /**
     * A struct for [vbase], which nothing defines: its vptr, then the [part] something defines [within]
     * bytes in, sized to the [room] the class leaves it. It fills an empty placeholder where one stands.
     */
    private fun synthesized(vbase: ClassDecl, part: DataType, within: Int, room: Int, at: String): Structure? {
        val ptr = program.defaultPointerSize
        val ns = vbase.ns?.takeUnless { it.isGlobal }
        if (ns == null || within < ptr || within + part.length > room) return null
        val vftable = dtm.getDataType(ClassNaming.vftablePath(ns))
        val category = ns.parentNamespace.getPathList(true)
            .fold(CategoryPath.ROOT) { path, seg -> CategoryPath(path, seg) }
        val placeholder = lookup(vbase).firstOrNull { it.isZeroLength }
        val struct = (placeholder ?: StructureDataType(category, ns.name, 0, dtm)).apply {
            growStructure(room)
            replaceAtOffset(0, PointerDataType(vftable, ptr, dtm), ptr, ClassUtils.VFPTR, "vtable pointer")
            replaceAtOffset(within, part, part.length, ClassNaming.baseFieldName(false, part.name, 1), "public base")
            description = "Defined nowhere: built off its RTTI, its size guessed from the $room bytes $at leaves it"
        }
        degradation("vbase-size-guessed", at, "$room bytes from the deriving class")
        return struct.takeIf(dtm::contains) ?: dtm.resolve(
            struct,
            DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER,
        ) as? Structure
    }

    /** Whether [vbaseAt] puts a virtual base inside [this], logging why not where it doesn't. */
    private fun Structure.isInside(vbaseAt: Int?, at: String): Boolean = when (vbaseAt) {
        // A nearly-empty virtual base can be the primary one, sharing the class's vptr: nothing to place.
        0 -> false.also { debug("vbase-primary-from-vtable") }

        in 1..<length -> true

        // Right past the end: this struct is only a base subobject; the deriving class places the virtual base.
        length -> false.also { debug("vbase-past-base-subobject", at) }

        else -> false.also {
            degradation("vbase-offset-unreadable", at, "the ${abi.virtualBaseRecord} reads ${vbaseAt ?: "nothing"}")
        }
    }

    private fun Structure.takeAcceptable() = takeUnless { it.isZeroLength }

    /** The bytes from [offset] to the next defined component or the end. */
    private fun Structure.roomAt(offset: Int) =
        (definedComponents.map { it.offset }.filter { it > offset }.minOrNull() ?: length) - offset

    /** [cls]'s non-empty struct, by [lookup]. */
    private fun structFor(cls: ClassDecl) = lookup(cls).firstNotNullOfOrNull { it.takeAcceptable() }

    /** What may be [cls]'s struct, empty or not: by its namespace, then as [recorded]. */
    private fun lookup(cls: ClassDecl) = listOfNotNull(
        when (val namespace = cls.ns) {
            is GhidraClass -> DataTypeUtilities.findExistingClassStruct(dtm, namespace)

            else if namespace?.isGlobal == false -> DataTypeUtilities.findDataType(
                dtm,
                namespace.parentNamespace,
                namespace.name,
                Structure::class.java,
            )

            else -> null
        },
        recorded(cls),
    )

    /** The struct a stabs import recorded for [cls]: by its namespace, else by its qualified name. */
    private fun recorded(cls: ClassDecl): Structure? {
        val entry = (cls.ns as? GhidraClass)?.let { record[it.id] } ?: recordByName[cls.qualifiedName]
        return entry?.structId?.let(dtm::getDataType) as? Structure
    }

    /** [cls]'s struct, else the first defined one down its first non-virtual bases, with its offset in [cls]. */
    private fun definedPart(cls: ClassDecl, depth: Int = 0): Pair<DataType, Int>? = structFor(cls)?.let { it to 0 }
        ?: cls.bases.takeIf { depth < MAX_DEPTH }.orEmpty()
            .filterNot { it.isVirtual }.minByOrNull { it.offset ?: 0 }
            ?.let { next ->
                definedPart(next.cls, depth + 1)?.let { (dt, at) -> dt to at + (next.offset ?: 0).toInt() }
            }

    private companion object {
        const val MAX_DEPTH = 16
    }
}

/** A class's name with its enclosing namespaces: its namespace's where it has one. */
val ClassDecl.qualifiedName: String get() = ns?.takeUnless { it.isGlobal }?.getName(true) ?: name
