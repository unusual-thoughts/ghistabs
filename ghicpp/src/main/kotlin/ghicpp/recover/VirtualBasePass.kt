package ghicpp.recover

import ghicpp.*
import ghicpp.ClassHierarchyRecords.Companion.readClassRecord
import ghicpp.abi.CxxAbi
import ghidra.program.database.data.DataTypeUtilities
import ghidra.program.model.data.*
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidrakt.*
import ghidrakt.diagnose.DiagnosticSink

/**
 * Places the virtual bases a class struct lacks where its [abi]'s records say they are
 * ([ClassDecl.virtualBases]). A base nothing defines is built off its RTTI, a vptr then the first base of
 * it something defines; where that doesn't fit, that part alone is placed.
 *
 * A class's struct is found by its namespace, else by the stabs import's class record ([readClassRecord]).
 * Anything already there, or that would not fit, is left and reported.
 */
class VirtualBasePass(private val program: Program, private val abi: CxxAbi, sink: DiagnosticSink) :
    DiagnosticSink by sink {
    private val dtm = program.dataTypeManager
    private val record = program.readClassRecord().orEmpty()

    /** [record] by qualified class name, for a class whose labels sit outside its class's namespace. */
    private val recordByName by lazy {
        record.mapNotNull { (id, entry) -> program.symbolTable.getSymbol(id)?.getName(true)?.let { it to entry } }
            .toMap()
    }

    /** Places each of [classes]' virtual bases; returns how many it placed. */
    fun placeAll(classes: Collection<ClassDecl>): Int = classes.sumOf { cls ->
        val struct = structFor(cls) ?: return@sumOf 0
        val vbases = cls.virtualBases
        val count = struct.definedComponents.count { it.isBaseField() } + vbases.size
        vbases.count { struct.place(it, count, unbuilt = cls.vftables.isEmpty()) }
    }

    private fun Structure.place(vbase: ClassBase, count: Int, unbuilt: Boolean): Boolean {
        val name = vbase.cls.qualifiedName
        val at = pathName.member(name)
        val vbaseAt = vbase.offset?.toInt().takeIf { isInside(it, at, unbuilt) } ?: return false

        val (found, foundWithin) = definedPart(vbase.cls) ?: return false.also {
            degradation("vbase-undefined", at, "nothing defines it or a base of it")
        }
        // Placed already, by the stabs or an earlier run.
        getComponentAt(vbaseAt)?.takeIf { it.offset == vbaseAt }?.dataType?.name?.let { existing ->
            if (existing == name.leafName || existing == found.name) return false
        }
        val (dt, within) = synthesized(vbase.cls, found, foundWithin, roomAt(vbaseAt), at)?.let { it to 0 }
            ?: (found to foundWithin)

        val offset = vbaseAt + within
        layoutProblem(offset, dt)?.let { return false.also { _ -> degradation("vbase-layout-failed", at, it) } }

        val part = "; only its ${dt.name} at +$within is defined"
            .takeUnless { within == 0 && dt.name == name.leafName }.orEmpty()
        placeBase(
            this,
            offset,
            dt,
            isVirtual = true,
            "${vbase.access.name.lowercase()} virtual $name at +0x${vbaseAt.toString(
                16,
            )}, by ${vbase.offsetSourceName()}$part",
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
        val category = ns.parentNamespace.path.toCategoryPath()
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

    private fun ClassBase.offsetSourceName() =
        if (offsetSource == SourceType.ANALYSIS) "its vftables" else "the ${abi.virtualBaseRecord}"

    /** Whether [vbaseAt] puts a virtual base inside [this], logging why not where it doesn't. */
    private fun Structure.isInside(vbaseAt: Int?, at: String, unbuilt: Boolean): Boolean = when (vbaseAt) {
        // A nearly-empty virtual base can be the primary one, sharing the class's vptr: nothing to place.
        0 -> false.also { debug("vbase-primary-from-vtable") }

        in 1..<length -> true

        // Right past the end: this struct is only a base subobject; the deriving class places the virtual base.
        length -> false.also { debug("vbase-past-base-subobject", at) }

        // No object of a class with no vftable here is built here, as a dllimported std::basic_iostream<char>:
        // nothing stores its vbtable, and the classes deriving from it place the virtual base themselves.
        null if unbuilt -> false.also { debug("vbase-offset-unknown-unbuilt", at) }

        else -> false.also {
            degradation("vbase-offset-unreadable", at, "the ${abi.virtualBaseRecord} reads ${vbaseAt ?: "nothing"}")
        }
    }

    private fun Structure.takeAcceptable() = takeUnless { it.isZeroLength }

    /** [cls]'s non-empty struct, by [lookup]. */
    private fun structFor(cls: ClassDecl) = lookup(cls).firstNotNullOfOrNull { it.takeAcceptable() }

    /**
     * What may be [cls]'s struct, empty or not: by its namespace, then where a class pass files it
     * ([classStruct]), then as [recorded].
     */
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
        (cls.ns as? GhidraClass)?.let(program::classStruct),
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
