package ghistabs.materialize

import ghicpp.*
import ghidra.program.model.data.DataTypeComponent
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.data.Undefined1DataType
import ghidra.program.model.gclass.ClassUtils
import ghidrakt.*
import ghidrakt.diagnose.DiagnosticSink
import ghistabs.index.vptrOffsetBytesOf
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl

/**
 * Where a polymorphic class's `{vfptr}` goes, and what happens to the base subobject that would
 * otherwise own it. See [VfptrModel] for what the choice costs a virtual call. [ClassStructBuilder]'s, which
 * runs it on each class in its turn.
 */
internal class VfptrPlacer(private val registry: DtmRegistry, private val model: VfptrModel, sink: DiagnosticSink) :
    DiagnosticSink by sink {
    private val dtm = registry.dtm
    private val splitter = BaseSplitter(registry, sink)

    /**
     * Put `{vfptr}` where the stab says the vptr is, as a pointer to the own vftable of the class
     * [classPath] names, its namespace path with the class itself last.
     * [classBody] is the class being laid, [structDt] its Structure, and [polyBase] the caller's
     * [ghistabs.index.firstPolymorphicBase], so the base graph is walked once per class.
     */
    fun place(
        structDt: Structure,
        classPath: List<String>,
        classBody: TypeDecl.Aggregate<GlobalTypeId>,
        polyBase: TypeDecl.Aggregate.Base<GlobalTypeId>?,
    ) {
        val vfptrName = ClassUtils.VFPTR
        val parserVptrOffset = classBody.vptrOffsetBytesOf()

        val targetOffset = parserVptrOffset ?: 0
        val existingComp = runCatching { structDt.getComponentAt(targetOffset) }.getOrNull()
        val snapshot = existingComp?.let {
            FirstComponentSnapshot(
                fieldName = it.fieldName,
                offsetBytes = it.offset,
                isUndefined = it.dataType is Undefined1DataType,
            )
        }

        val action = chooseVfptrAction(
            hasPolymorphicBaseSubobject = polyBase != null,
            parserVptrOffsetBytes = parserVptrOffset,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = vfptrName,
        )

        when (action) {
            is VfptrAction.SkipInheritedFromBase -> if (model == VfptrModel.SPLIT_BASE && splitter.splitBase(
                    structDt,
                    classPath,
                    targetOffset,
                    polyBase?.ownerOfInheritedVptr(structDt) ?: existingComp,
                )
            ) {
                debug("vfptr-split-from-base")
            } else {
                debug("vfptr-inherited-from-base")
            }

            is VfptrAction.AlreadyCanonical -> return

            is VfptrAction.Insert -> {
                val ptrToVtable = ownVfptr(classPath)
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
                val ptrToVtable = ownVfptr(classPath)
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
                classPath.last(),
                "cannot place {vfptr} at +${action.offsetBytes} (occupied by ${action.occupantFieldName})",
            )
        }
    }

    /**
     * The base subobject whose vptr this class inherits: [polyBase]'s own component. Not whatever
     * sits at the class's declared vptr offset, which a class that declares none puts at 0 — gcc 2.x
     * `Diamond : Left, Right, Named` inherits Named's vptr at +24, and splitting `Left` at 0 instead
     * wrote the pointer over its `_vb$`. Null for a virtual base, whose stab offset is not where its
     * component sits (0 under gcc 2.x, a vtable offset under Itanium).
     */
    private fun TypeDecl.Aggregate.Base<GlobalTypeId>.ownerOfInheritedVptr(structDt: Structure) = when {
        isVirtual -> null

        else -> runCatching { structDt.getComponentAt((offsetBits / 8).toInt()) }.getOrNull()
            ?.takeIf(DataTypeComponent::isBaseField)
    }

    /** {vfptr} points at the function-pointer array at the vtable's address point, not at the record. */
    private fun ownVfptr(classPath: List<String>) = PointerDataType.getPointer(registry.vftableOf(classPath), dtm)
}

/** Component snapshot at a target offset, fed into [chooseVfptrAction]. */
data class FirstComponentSnapshot(val fieldName: String?, val offsetBytes: Int, val isUndefined: Boolean)

sealed class VfptrAction {
    object SkipInheritedFromBase : VfptrAction()
    data class Insert(val offsetBytes: Int) : VfptrAction()
    data class Replace(val offsetBytes: Int, val wasFieldName: String) : VfptrAction()
    object AlreadyCanonical : VfptrAction()
    data class CollisionAt(val offsetBytes: Int, val occupantFieldName: String) : VfptrAction()
}

/** What to do with the component already sitting where the vptr belongs. Pure, so it unit-tests. */
fun chooseVfptrAction(
    hasPolymorphicBaseSubobject: Boolean,
    parserVptrOffsetBytes: Int?,
    componentAtTargetOffset: FirstComponentSnapshot?,
    canonicalVfptrFieldName: String,
): VfptrAction {
    if (hasPolymorphicBaseSubobject) return VfptrAction.SkipInheritedFromBase

    val targetOffset = parserVptrOffsetBytes ?: 0

    if (
        componentAtTargetOffset != null &&
        componentAtTargetOffset.offsetBytes == targetOffset &&
        componentAtTargetOffset.fieldName == canonicalVfptrFieldName
    ) {
        return VfptrAction.AlreadyCanonical
    }

    if (componentAtTargetOffset == null || componentAtTargetOffset.isUndefined) {
        return VfptrAction.Insert(targetOffset)
    }

    // An unresolved or synthesized base at the vptr offset: polymorphism was never proven, but the
    // stab layout still says a base owns the word.
    if (componentAtTargetOffset.fieldName?.let(ClassNaming::isBaseField) == true) {
        return VfptrAction.SkipInheritedFromBase
    }

    return if (componentAtTargetOffset.fieldName?.let(::isVptrFieldName) == true) {
        VfptrAction.Replace(targetOffset, componentAtTargetOffset.fieldName)
    } else {
        VfptrAction.CollisionAt(targetOffset, componentAtTargetOffset.fieldName ?: "<anon>")
    }
}
