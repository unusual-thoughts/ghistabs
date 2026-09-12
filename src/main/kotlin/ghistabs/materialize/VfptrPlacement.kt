package ghistabs.materialize

import ghidra.program.model.data.DataTypeComponent
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.data.Undefined1DataType
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.listing.Program
import ghistabs.diagnose.DiagnosticSink
import ghistabs.materialize.abi.Itanium
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl
import ghistabs.parse.isVptrFieldName

/**
 * Where a polymorphic class's `{vfptr}` goes, and what happens to the base subobject that would
 * otherwise own it. See [VfptrModel] for what the choice costs a virtual call.
 */
internal class VfptrPlacement(
    private val registry: DataTypeRegistry,
    private val program: Program,
    private val model: VfptrModel,
    private val sink: DiagnosticSink,
) : DiagnosticSink by sink {

    /**
     * Put `{vfptr}` where the stab says the vptr is, as [ownVfptr] — a pointer to *this* class's
     * vftable. [className] and [classBody] are the class being built, [structDt] its materialized
     * Structure, and [hasPolymorphicBaseSubobject] the caller's answer, so the base graph is walked
     * once per class rather than once here and again there.
     */
    fun place(
        structDt: Structure,
        className: String,
        classBody: TypeDecl.Aggregate<GlobalTypeId>,
        hasPolymorphicBaseSubobject: Boolean,
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

        val action = chooseVfptrAction(
            hasPolymorphicBaseSubobject = hasPolymorphicBaseSubobject,
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
            ?: (vptrOffset - baseComp.offset)
        val split = splitAround(baseDt.length, vptrInBase, ptr) ?: return false
        val baseOff = baseComp.offset
        val tailFrom = vptrInBase + ptr

        val head = split.head?.let { baseFieldsRun(baseDt, it.from, it.until) }
        val tail = split.tail?.let { baseFieldsRun(baseDt, it.from, it.until) }
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
     * One contiguous run of [baseDt]'s bytes, `[from, until)`, as a struct: the base subobject's
     * fields with the vptr word taken out. Null when empty. Shared by every class deriving from
     * that base, so one extra type per polymorphic class rather than one per inheritance edge.
     *
     * The bounds are in the name: the registry caches on (category, name) alone, so two runs of one
     * base differing only in extent would collide.
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

/** A half-open byte range `[from, until)` of a base subobject. */
data class Run(val from: Int, val until: Int) {
    val length get() = until - from
}

/** What a vptr leaves of a base subobject: the fields before it and the fields after it. */
data class BaseSplit(val head: Run?, val tail: Run?)

/**
 * The runs a vptr at [vptrInBase] leaves of a [baseLength]-byte base. Null when the pointer does not
 * fit inside the base, or when it covers the base whole and there is nothing left to embed.
 *
 * One run is empty whenever the vptr is at the start (Itanium) or the end (gcc 2.x at depth 1),
 * which keeps the subobject a single `_base_` component. Deeper in a gcc 2.x chain both are real:
 * `TiXmlElement` inherits `location`/`userData` before the vptr and `value` after.
 */
fun splitAround(baseLength: Int, vptrInBase: Int, ptrSize: Int): BaseSplit? {
    if (vptrInBase < 0 || vptrInBase + ptrSize > baseLength) return null
    val head = Run(0, vptrInBase).takeIf { it.length > 0 }
    val tail = Run(vptrInBase + ptrSize, baseLength).takeIf { it.length > 0 }
    return if (head == null && tail == null) null else BaseSplit(head, tail)
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
    if (componentAtTargetOffset.fieldName?.let(Itanium::isBaseField) == true) {
        return VfptrAction.SkipInheritedFromBase
    }

    return if (componentAtTargetOffset.fieldName?.let(::isVptrFieldName) == true) {
        VfptrAction.Replace(targetOffset, componentAtTargetOffset.fieldName)
    } else {
        VfptrAction.CollisionAt(targetOffset, componentAtTargetOffset.fieldName ?: "<anon>")
    }
}

/**
 * Where a polymorphic class's `{vfptr}` comes from, which decides whether a virtual call resolves to
 * a named slot or overruns into `vfptr[N]`.
 *
 * The vptr sits inside the primary base subobject, so a derived class can only carry a pointer to
 * its **own** vftable if something gives way, and the static type of that field is what the
 * decompiler indexes. With one shared field typed `<Root>_vftable *`, every derived slot lands past
 * the end of the root's table: `xmltest_gcc421` renders 31 of its 40 virtual calls as
 * `vfptr[4].~TiXmlBase` and never mentions a derived vftable type at all.
 *
 * A third shape exists: Ghidra's own `RecoveredClassHelper` expands the base subobject away
 * entirely and puts `vftablePtr` at offset 0, trading the `_base_` component for the pointer.
 */
enum class VfptrModel {
    /** One `{vfptr}` on the root of each hierarchy, inherited through `_base_`. Derived slots overrun. */
    INHERITED,

    /**
     * Each polymorphic class owns a `{vfptr}` typed to its own vftable, and embeds its primary base
     * as that base's fields *without* the vptr — one extra struct per polymorphic class, shared by
     * every class that derives from it. Keeps the `_base_` subobject component that
     * [ghistabs.materialize.Layout] models inheritance with.
     */
    SPLIT_BASE,
}
