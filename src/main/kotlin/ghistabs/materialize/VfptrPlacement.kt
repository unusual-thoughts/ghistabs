package ghistabs.materialize

import ghidra.program.model.data.DataTypeComponent
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.data.Undefined1DataType
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.listing.Program
import ghistabs.diagnose.DiagnosticSink
import ghistabs.index.TypeGraph
import ghistabs.materialize.itanium.FirstComponentSnapshot
import ghistabs.materialize.itanium.Layout
import ghistabs.materialize.itanium.VfptrAction
import ghistabs.materialize.itanium.VfptrModel
import ghistabs.materialize.itanium.hasPolymorphicBaseSubobject
import ghistabs.materialize.itanium.vptrOffsetBytesOf
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl

/**
 * Where a polymorphic class's `{vfptr}` goes, and what happens to the base subobject that would
 * otherwise own it. See [VfptrModel] for what the choice costs a virtual call.
 */
internal class VfptrPlacement(
    private val registry: DataTypeRegistry,
    private val types: TypeGraph,
    private val program: Program,
    private val model: VfptrModel,
    private val sink: DiagnosticSink,
) : DiagnosticSink by sink {

    /**
     * Put `{vfptr}` where the stab says the vptr is, as [ownVfptr] — a pointer to *this* class's
     * vftable. [className] and [classBody] are the class being built; [structDt] is its materialized
     * Structure.
     */
    fun place(
        structDt: Structure,
        className: String,
        classBody: TypeDecl.Aggregate<GlobalTypeId>,
        ownVfptr: () -> Pointer,
    ) {
        val vfptrName = ClassUtils.VFPTR
        val parserVptrOffset = vptrOffsetBytesOf(classBody)

        val targetOffset = parserVptrOffset ?: 0
        val existingComp = runCatching { structDt.getComponentAt(targetOffset) }.getOrNull()
        val snapshot = existingComp?.let {
            FirstComponentSnapshot(
                fieldName = it.fieldName,
                offsetBytes = it.offset,
                isUndefined = it.dataType is Undefined1DataType,
            )
        }

        val action = Layout.chooseVfptrAction(
            hasPolymorphicBaseSubobject = types.hasPolymorphicBaseSubobject(classBody),
            parserVptrOffsetBytes = parserVptrOffset,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = vfptrName,
        )

        when (action) {
            is VfptrAction.SkipInheritedFromBase ->
                if (model == VfptrModel.SPLIT_BASE &&
                    splitBase(structDt, className, targetOffset, existingComp, ownVfptr)
                ) {
                    debug("vfptr-split-from-base")
                } else {
                    debug("vfptr-inherited-from-base")
                }

            is VfptrAction.AlreadyCanonical -> return

            is VfptrAction.Insert -> {
                val ptrToVtable = ownVfptr()
                structDt.insertAtOffset(
                    action.offsetBytes,
                    ptrToVtable,
                    ptrToVtable.length,
                    vfptrName,
                    "vtable pointer",
                )
                debug("vfptr-inserted")
            }

            is VfptrAction.Replace -> {
                val ptrToVtable = ownVfptr()
                structDt.replaceAtOffset(
                    action.offsetBytes,
                    ptrToVtable,
                    ptrToVtable.length,
                    vfptrName,
                    "vtable pointer (was: ${action.wasFieldName})",
                )
                debug("vfptr-normalized")
            }

            is VfptrAction.CollisionAt -> degradation(
                "vfptr-collision",
                className,
                "cannot place {vfptr} at +${action.offsetBytes} (occupied by ${action.occupantFieldName})",
            )
        }
    }

    /**
     * Give this class its own `{vfptr}` where a polymorphic base subobject would otherwise own it:
     * the pointer goes at the vptr offset and the base is re-embedded as its *fields*, the same
     * bytes minus the vptr it no longer holds ([VfptrModel.SPLIT_BASE]).
     *
     * What matters is the pointer's static type. A shared `{vfptr}` is typed with whichever class
     * declares it, so every derived slot indexes past the end of that class's vftable and the
     * decompiler falls back to `vfptr[4].~TiXmlBase`. The `_base_` component survives, so the
     * subobject still models the inheritance.
     *
     * False when the base cannot be split, leaving the caller to report the inherited case.
     */
    private fun splitBase(
        structDt: Structure,
        className: String,
        vptrOffset: Int,
        baseComp: DataTypeComponent?,
        ownVfptr: () -> Pointer,
    ): Boolean {
        val baseDt = baseComp?.dataType as? Structure ?: return false
        val ptr = program.defaultPointerSize
        // Where the vptr sits *within* the base, read off the base itself rather than assumed: the
        // Itanium ABI puts it at 0, gcc 2.x appends it after the class's own fields. Classes are
        // built bases-first, so a polymorphic base already carries its own placed {vfptr}. A base
        // that carries none — reached through the base-field branch of chooseVfptrAction, where
        // polymorphism was never proven — falls back to where this class says its vptr is.
        val vptrInBase = baseDt.definedComponents.firstOrNull { it.fieldName == ClassUtils.VFPTR }?.offset
            ?: (vptrOffset - baseComp.offset).takeIf { it >= 0 && it + ptr <= baseDt.length }
            ?: return false
        val baseOff = baseComp.offset
        val tailFrom = vptrInBase + ptr

        // The vptr splits the inherited data into up to two runs. One of them is empty whenever the
        // vptr is at the start (Itanium) or the end (gcc 2.x at depth 1), which is the common case
        // and keeps the subobject a single `_base_` component. Deeper in a gcc 2.x chain both runs
        // are real — `TiXmlElement` inherits `location`/`userData` before the vptr and `value`
        // after — so the subobject is spliced as a head and a tail rather than dropped.
        val head = baseFieldsRun(baseDt, 0, vptrInBase)
        val tail = baseFieldsRun(baseDt, tailFrom, baseDt.length)
        if (head == null && tail == null) return false

        val vfptr = ownVfptr()
        return runCatching {
            head?.let { structDt.replaceAtOffset(baseOff, it, it.length, baseComp.fieldName, baseComp.comment) }
            structDt.replaceAtOffset(baseOff + vptrInBase, vfptr, vfptr.length, ClassUtils.VFPTR, "vtable pointer")
            tail?.let {
                val name = if (head == null) baseComp.fieldName else "${baseComp.fieldName}_tail"
                structDt.replaceAtOffset(baseOff + tailFrom, it, it.length, name, baseComp.comment)
            }
        }.onFailure {
            degradation("vfptr-split-failed", className, "${baseDt.name} at +$baseOff: ${it.message}")
        }.isSuccess
    }

    /**
     * One contiguous run of [baseDt]'s bytes, `[from, until)`, as a struct of its own: the base
     * subobject's fields with the vptr word taken out. Null when the run is empty. Shared across
     * every class deriving from that base, which is what keeps this one extra type per polymorphic
     * class instead of one per inheritance edge.
     *
     * The bounds are in the name because they are what the type *is*: the registry caches on
     * (category, name) alone, so two runs of one base that differ only in extent would otherwise
     * collide and the second class would silently receive the first's struct.
     */
    private fun baseFieldsRun(baseDt: Structure, from: Int, until: Int): Structure? {
        if (until <= from) return null
        val name = "${baseDt.name}_fields_${from}_$until"
        return registry.getOrRegister<Structure>(baseDt.categoryPath, name) {
            StructureDataType(baseDt.categoryPath, name, until - from, program.dataTypeManager).apply {
                description = "${baseDt.name} as a base subobject (+$from..$until): its fields " +
                    "without the vptr the deriving class now owns"
                baseDt.definedComponents
                    .filter { it.offset >= from && it.offset + it.length <= until }
                    .forEach {
                        runCatching {
                            replaceAtOffset(it.offset - from, it.dataType, it.length, it.fieldName, it.comment)
                        }
                    }
            }
        }
    }
}
