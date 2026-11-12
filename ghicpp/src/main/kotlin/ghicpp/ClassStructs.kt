package ghicpp

import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeComponent
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidrakt.componentsOverlapping
import ghidrakt.diagnose.DiagnosticSink
import ghidrakt.holds
import ghidrakt.includes
import ghidrakt.lay
import ghidrakt.range
import ghidrakt.stretch
import ghidrakt.withLength

/**
 * Describes this struct as [owner]'s [table], led by the offset tag Ghidra 12.1's `ClassUtils.isVTable`
 * matches: the [offset] of the `{vfptr}` that points at it. Without a known, non-negative offset there
 * is no tag, since a wrong one would misplace Ghidra's vxtable replacement.
 */
fun Structure.describeVxTable(owner: String, table: String, offset: Long?) {
    val vfptrOffset = offset?.takeIf { it >= 0 }
    val text = "$owner's $table: what its {${ClassUtils.VFPTR}}" +
        vfptrOffset?.let { " at +$it" }.orEmpty() + " points at"
    val tag = vfptrOffset?.let { ClassUtils::class.createVxTableDescriptionOffsetTag(it) }
    description = listOfNotNull(tag, text).joinToString(" ")
}

/** Offset of the first `{vfptr}` in this struct, its own or one inherited through a base subobject. */
fun Structure.vfptrOffset(): Int? = definedComponents.firstNotNullOfOrNull { c ->
    when {
        c.fieldName == ClassUtils.VFPTR -> c.offset
        c.isBaseField() -> (c.dataType as? Structure)?.vfptrOffset()?.let { c.offset + it }
        else -> null
    }
}

/** The direct base whose `{vfptr}` the class's own is, when it shares one. */
internal fun Structure.primaryBase(): String? {
    val vfptr = vfptrOffset() ?: return null
    return definedComponents.firstOrNull { c ->
        c.isBaseField() && (c.dataType as? Structure)?.vfptrOffset()?.let { c.offset + it } == vfptr
    }?.dataType?.name
}

/**
 * Offset of the `{vfptr}` inside base subobject [base], where a gcc 2.x secondary vtable's pointer
 * sits. Matches only a whole base: a split primary base has no vptr of its own.
 */
internal fun Structure.vfptrOffsetOfBase(base: String): Int? = definedComponents.firstNotNullOfOrNull { c ->
    val dt = c.dataType as? Structure
    when {
        !c.isBaseField() || dt == null -> null
        dt.name == base.leafName -> dt.vfptrOffset()?.let { c.offset + it }
        else -> dt.vfptrOffsetOfBase(base)?.let { c.offset + it }
    }
}

/** [ClassNaming.isBaseField], off a live component instead of a bare field name. */
fun DataTypeComponent.isBaseField() = ClassNaming.isBaseField(fieldName.orEmpty())

/** Lays [dt] at [offset] in [struct] as a base subobject, and reports how that went. */
fun DiagnosticSink.placeBase(
    struct: Structure,
    offset: Int,
    dt: DataType,
    isVirtual: Boolean,
    comment: String,
    fieldName: String,
    qualifiedName: String,
) {
    val (applied, failed) = if (isVirtual) {
        "vbase-applied" to "vbase-layout-failed"
    } else {
        "inheritance-applied" to "base-layout-failed"
    }
    runCatching { struct.replaceAtOffset(offset, dt, dt.length, fieldName, comment) }
        .onSuccess { debug(applied) }
        .onFailure {
            degradation(failed, qualifiedName.member(dt.name), it.message)
            if (!isVirtual) debug("inheritance-failed")
        }
}

/** The class's struct where `RecoverClassesFromRTTIScript` files it. */
fun Program.classStruct(ns: GhidraClass) =
    dataTypeManager.getDataType(ClassNaming.vftableCategory(ns), ns.name) as? Structure

/**
 * Gives [ns] a [classStruct] of [size] bytes, or grows its own to them. Where its last field is one of its own
 * `<Class>_data` structs, or, split around a deriving class's vptr, its own `_fields` run ending in one, that grows
 * with it, so the fields its constructors store past the old end are refilled there. A base's `_fields` part keeps
 * its size: it is the base's, which grew none.
 */
fun Program.sizeClassStruct(ns: GhidraClass, size: Int) {
    if (size <= 0) return
    when (val struct = classStruct(ns)) {
        null -> dataTypeManager.addDataType(
            StructureDataType(ClassNaming.vftableCategory(ns), ns.name, size),
            DataTypeConflictHandler.KEEP_HANDLER,
        )

        else if struct.isZeroLength -> struct.growStructure(size)

        else if struct.length < size -> {
            val last = struct.definedComponents.lastOrNull()?.takeIf { it.endOffset == struct.length - 1 }
            struct.growStructure(size - struct.length)
            if (last != null) struct.stretchOwnTail(struct, last, size)
        }
    }
}

/**
 * Lays [member] at [at] in [owner], a class struct, as a member object, and reports how that went. It goes down
 * through the struct holding all of it, a base subobject or, the base split around a deriving class's vptr
 * ([VfptrModel.SPLIT_BASE]), the `_fields` run the class's own fields moved into, to the class's own
 * `<Class>_data` struct, where it goes over the plain fields there. That struct [stretch]es to hold it where it
 * starts before or ends past it, and [owner] grows where it ends past the end. Anywhere else it goes only over
 * undefined bytes: a vptr, another class's fields or another member in the way leaves it unplaced, with a warning.
 */
internal fun DiagnosticSink.placeMember(owner: Structure, at: Int, member: Structure) {
    if (member == owner) return
    val field = ClassNaming.fieldName(at)
    fun unplaced(into: Structure, why: List<DataTypeComponent>) = degradation(
        "member-unplaced",
        "${owner.name}::$field",
        "${member.name} overlaps ${why.joinToString { it.describe() }}" +
            " in ${into.name}".takeIf { into != owner }.orEmpty(),
    )
    var into = owner
    var offset = at
    var ownData = false
    while (!ownData) {
        val range = offset.withLength(member.length)
        val inWay = into.componentsOverlapping(range).filterNot { it.isAt(offset, member) }
        val part = inWay.singleOrNull()?.takeIf { it.dataType is Structure }
        when {
            inWay.isEmpty() -> break

            part != null && part.range.includes(range) -> {
                ownData = owner.isOwnData(part)
                offset -= part.offset
                into = part.dataType as Structure
            }

            part != null && into == owner && owner.isOwnData(part) -> {
                val start = minOf(part.offset, offset)
                into = owner.stretch(part, range)
                offset -= start
                ownData = true
            }

            else -> return unplaced(into, inWay)
        }
    }
    val clash = into.componentsOverlapping(offset, member.length)
        .filter { it.dataType is Structure && !it.isAt(offset, member) }
    if (clash.isNotEmpty()) return unplaced(into, clash)
    runCatching { into.lay(offset, member, field, "member or base") }
        .onSuccess { debug("member-placed", "${member.name} at +$at in ${owner.name}") }
        .onFailure { degradation("member-unplaced", "${owner.name}::$field", it.message) }
}

/** Whether this is [member] laid at [at] already. */
private fun DataTypeComponent.isAt(at: Int, member: Structure) = dataType == member && offset == at

private fun DataTypeComponent.describe() = "${fieldName ?: dataType.name} at +0x${offset.toString(16)}"

/**
 * Stretches [last], this struct's last field, on to [end], where it is one of [owner]'s own `<Class>_data` structs,
 * or one of its own `_fields` runs, whose own last field stretches with it in turn.
 */
private fun Structure.stretchOwnTail(owner: Structure, last: DataTypeComponent, end: Int) {
    if (!owner.isOwnData(last) && !owner.isOwnFields(last)) return
    val tail = (last.dataType as Structure).definedComponents.lastOrNull()
        ?.takeIf { owner.isOwnFields(last) && it.endOffset == last.length - 1 }
    val offset = last.offset
    val inner = stretch(last, offset..<end)
    if (tail != null) inner.stretchOwnTail(owner, tail, end - offset)
}

/** Whether [part] holds one of this class struct's own `<Class>_data` structs, filed beside it. */
fun Structure.isOwnData(part: DataTypeComponent) = (part.dataType as? Structure)?.let {
    it.categoryPath == categoryPath && it.name.startsWith(name + ClassNaming.DATA)
} == true

/**
 * Whether [part] holds one of this class struct's own `<Class>_fields` runs, its own fields and those of its
 * bases laid inside it, without the vptr a deriving class took over ([BaseSplitter]); filed beside it, or
 * beside its self-base.
 */
fun Structure.isOwnFields(part: DataTypeComponent) = (part.dataType as? Structure)?.let {
    it.categoryPath.isAncestorOrSelf(categoryPath) && it.name.startsWith(name + ClassNaming.FIELDS)
} == true

/**
 * This class struct's own `<Class>_data` structs, by their offset into it: those it holds and, its fields split
 * around a deriving class's vptr ([VfptrModel.SPLIT_BASE]), those inside its own `_fields` runs.
 */
fun Structure.ownData(): List<Pair<Int, Structure>> = definedComponents.flatMap { part ->
    when {
        isOwnData(part) -> listOf(part.offset to part.dataType as Structure)

        isOwnFields(part) -> (part.dataType as Structure).definedComponents.filter { isOwnData(it) }
            .map { part.offset + it.offset to it.dataType as Structure }

        else -> emptyList()
    }
}

/** Why [dt] can't go at [at] in this over undefined bytes alone, or null where it can. */
fun Structure.layoutProblem(at: Int, dt: DataType): String? = when {
    at + dt.length > length -> "${dt.name} (${dt.length}b) at +$at overruns $length"
    componentsOverlapping(at, dt.length).isNotEmpty() -> "${dt.name} at +$at covers existing fields"
    else -> null
}

/**
 * Fills this, a class's self-base ([ClassUtils.getBaseClassDataTypePath]), with the fields of [cls] it holds
 * whole but the virtual bases, in place of any it has; [onFailure] hears of a field that wouldn't go.
 */
fun Structure.copyNonVirtualPart(cls: Structure, onFailure: (DataTypeComponent, Throwable) -> Unit = { _, _ -> }) {
    definedComponents.map { it.offset }.forEach(::clearAtOffset)
    cls.definedComponents.filter { (0..<length).holds(it) && !it.isVirtualBaseField() }.forEach {
        runCatching { replaceAtOffset(it.offset, it.dataType, it.length, it.fieldName, it.comment) }
            .onFailure { e -> onFailure(it, e) }
    }
}

/** Whether this is a virtual base's field. */
fun DataTypeComponent.isVirtualBaseField() = fieldName.orEmpty().startsWith(ClassNaming.VBASE_PREFIX)
