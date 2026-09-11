package ghistabs.materialize

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
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl
import ghistabs.parse.isVptrFieldName

/**
 * Where a polymorphic class's `{vfptr}` goes, and what happens to the base subobject that would
 * otherwise own it. Split out of `ClassBuilder` because it is one decision with two shapes — see
 * [VfptrModel] for why the choice matters to whether a virtual call resolves at all.
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
        val parserVptrOffset = classBody.fields
            .firstOrNull { isVptrFieldName(it.name) }
            ?.let { (it.offsetBits / 8).toInt() }

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
     * The point is the pointer's static type. A shared `{vfptr}` is typed with whichever class
     * declares it, so every derived slot indexes past the end of that class's vftable and the
     * decompiler falls back to `vfptr[4].~TiXmlBase`. One `<Base>_fields` struct serves every class
     * deriving from that base, so this costs one extra type per polymorphic class rather than one
     * per inheritance edge, and the `_base_` component survives to model the inheritance.
     *
     * Declines — leaving the caller to report the inherited case — unless the vptr sits at the very
     * start of the base subobject. gcc 2.x appends the vptr *after* a class's own fields instead
     * (`tinyxml_aout_gcc295.o` dispatches through `this + 0xc`), which would need the base split
     * into a prefix and a suffix around the pointer rather than simply shortened at the front.
     */
    private fun splitBase(
        structDt: Structure,
        className: String,
        vptrOffset: Int,
        baseComp: ghidra.program.model.data.DataTypeComponent?,
        ownVfptr: () -> Pointer,
    ): Boolean {
        val baseDt = baseComp?.dataType as? Structure ?: return false
        if (baseComp.offset != vptrOffset) return false
        val ptr = program.defaultPointerSize
        if (baseDt.length <= ptr) return false

        val fieldsName = "${baseDt.name}_fields"
        val fields = registry.getOrRegister<Structure>(baseDt.categoryPath, fieldsName) {
            StructureDataType(baseDt.categoryPath, fieldsName, baseDt.length - ptr, program.dataTypeManager).apply {
                description = "${baseDt.name} as a base subobject: its fields without the vptr the " +
                    "deriving class now owns"
                baseDt.definedComponents
                    .filter { it.offset >= ptr }
                    .forEach {
                        runCatching {
                            replaceAtOffset(it.offset - ptr, it.dataType, it.length, it.fieldName, it.comment)
                        }
                    }
            }
        }

        val vfptr = ownVfptr()
        return runCatching {
            structDt.replaceAtOffset(vptrOffset, vfptr, vfptr.length, ClassUtils.VFPTR, "vtable pointer")
            structDt.replaceAtOffset(vptrOffset + ptr, fields, fields.length, baseComp.fieldName, baseComp.comment)
        }.onFailure {
            degradation("vfptr-split-failed", className, "${baseDt.name} at +$vptrOffset: ${it.message}")
        }.isSuccess
    }
}
