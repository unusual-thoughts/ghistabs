package ghistabs.materialize.cpp

import ghidra.program.model.data.*
import ghidra.program.model.gclass.ClassUtils
import ghistabs.at
import ghistabs.diagnose.DiagnosticSink
import ghistabs.materialize.DataTypeRegistry
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl
import ghistabs.parse.isVptrFieldName
import ghistabs.parse.leafName

/**
 * Where a polymorphic class's `{vfptr}` goes, and what happens to the base subobject that would
 * otherwise own it. See [VfptrModel] for what the choice costs a virtual call. [ClassLayout]'s, which
 * runs it on each class in its turn.
 */
internal class VfptrPlacement(private val registry: DataTypeRegistry, private val model: VfptrModel) :
    DiagnosticSink by registry {
    private val dtm = registry.dtm

    /**
     * Put `{vfptr}` where the stab says the vptr is, as a pointer to the own vftable of the class
     * [classPath] names, its namespace path with the class itself last.
     * [classBody] is the class being laid, [structDt] its Structure, and [polyBase] the caller's
     * [ghistabs.index.TypeGraph.firstPolymorphicBase], so the base graph is walked once per class.
     */
    fun place(
        structDt: Structure,
        classPath: List<String>,
        classBody: TypeDecl.Aggregate<GlobalTypeId>,
        polyBase: TypeDecl.Aggregate.Base<GlobalTypeId>?,
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
            hasPolymorphicBaseSubobject = polyBase != null,
            parserVptrOffsetBytes = parserVptrOffset,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = vfptrName,
        )

        when (action) {
            is VfptrAction.SkipInheritedFromBase -> if (model == VfptrModel.SPLIT_BASE && splitBase(
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
        classPath: List<String>,
        vptrOffset: Int,
        baseComp: DataTypeComponent?,
    ): Boolean {
        val className = classPath.last()
        val baseDt = baseComp?.dataType as? Structure ?: return false
        val ptr = dtm.dataOrganization.pointerSize
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

        val vfptr = ownVfptr(classPath)
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
        return registry.getOrRegister<Structure>(baseDt.categoryPath.at(name)) {
            StructureDataType(baseDt.categoryPath, name, until - from, dtm).apply {
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

/**
 * `<Class>_vftable` under `/ClassDataTypes/<ns>/<Class>/`, the function-pointer array `{vfptr}` points
 * at, where `RecoveredClassHelper` and shift-S round-trip expect it. [classPath] is the class's
 * namespace path, the class itself last. Empty until the class pass fills it.
 */
internal fun DataTypeRegistry.vftableOf(classPath: List<String>) = ClassNaming.vftablePath(classPath).let { dtPath ->
    getOrRegister<Structure>(dtPath) {
        StructureDataType(dtPath.categoryPath, dtPath.dataTypeName, 0, dtm)
    }
}

/**
 * Describe [this] as [owner]'s [table], the one the `{vfptr}` at [vfptrOffset] in the class points at.
 * The description leads with the offset tag `ClassUtils.isVTable` (12.1+) recognises a table by, one
 * per table at its own `{vfptr}`'s offset, so a secondary carries the offset of the subobject it
 * serves. No offset, no tag: a guessed one would point Ghidra's vxtable replacement at the wrong word,
 * and a negative one can only come from a misread record.
 */
internal fun Structure.describeVxTable(owner: String, table: String, offset: Long?) {
    val vfptrOffset = offset?.takeIf { it >= 0 }
    val text = "$owner's $table: what its {${ClassUtils.VFPTR}}" +
        vfptrOffset?.let { " at +$it" }.orEmpty() + " points at"
    val tag = vfptrOffset?.let { ClassUtils::class.createVxTableDescriptionOffsetTag(it) }
    description = listOfNotNull(tag, text).joinToString(" ")
}

/**
 * Offset of the first `{vfptr}` in [this], looking through base subobjects in layout order — so it
 * finds the pointer a class inherits through its primary base as well as one it owns, wherever the
 * ABI put it (gcc 2.x appends it after the class's own fields).
 */
internal fun Structure.vfptrOffset(): Int? = definedComponents.firstNotNullOfOrNull { c ->
    when {
        c.fieldName == ClassUtils.VFPTR -> c.offset
        c.isBaseField() -> (c.dataType as? Structure)?.vfptrOffset()?.let { c.offset + it }
        else -> null
    }
}

/**
 * Offset in [this] of the `{vfptr}` inside the base subobject [base] names, looking through base
 * subobjects in layout order — where a gcc 2.x secondary vtable's pointer sits in the class. The base
 * is found by name, whole: a primary base [VfptrModel.SPLIT_BASE] took apart is a `_fields_` run
 * with no vptr left, and its table is the class's own.
 */
internal fun Structure.vfptrOffsetOfBase(base: String): Int? = definedComponents.firstNotNullOfOrNull { c ->
    val dt = c.dataType as? Structure
    when {
        !c.isBaseField() || dt == null -> null
        dt.name == base.leafName -> dt.vfptrOffset()?.let { c.offset + it }
        else -> dt.vfptrOffsetOfBase(base)?.let { c.offset + it }
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
    if (componentAtTargetOffset.fieldName?.let(ClassNaming::isBaseField) == true) {
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
     * [ClassNaming.baseFieldName] models inheritance with.
     */
    SPLIT_BASE,
}
