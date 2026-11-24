package ghicpp

import ghidra.program.database.data.DataTypeUtilities
import ghidra.program.model.data.*
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidrakt.*
import ghidrakt.diagnose.DiagnosticSink

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
 * Gives [ns] an empty [classStruct] where it has none. Done before any function moves into [ns]: a `__thiscall`
 * method of a class with no struct makes Ghidra add an empty placeholder to type its `this` with, in the class's
 * parent category (`/<Class>` for a global one), and its lookup (`findExistingClassStruct`) then takes that one over
 * the [classStruct], being the shorter path. Such a placeholder an earlier run left is replaced by the [classStruct],
 * so what it typed is typed with this.
 */
fun Program.stubClassStruct(ns: GhidraClass) {
    val struct = classStruct(ns) ?: dataTypeManager.addDataType(
        StructureDataType(ClassNaming.vftableCategory(ns), ns.name, 0),
        DataTypeConflictHandler.KEEP_HANDLER,
    ) as Structure
    val found = DataTypeUtilities.findExistingClassStruct(dataTypeManager, ns) ?: return
    if (found != struct && found.isZeroLength && found.description == GHIDRA_PLACEHOLDER) {
        dataTypeManager.replaceDataType(found, struct, false)
    }
}

/** The description `VariableUtilities` gives the placeholder struct it makes for a class with none. */
private const val GHIDRA_PLACEHOLDER = "PlaceHolder Class Structure"

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
            val last = struct.definedComponents.lastOrNull()?.takeIf { it.endsAtEndOf(struct) }
            struct.growStructure(size - struct.length)
            if (last != null) struct.stretchOwnTail(struct, last, size)
            struct.settleHolders()
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
 *
 * But for [owner]'s own vptr right where it goes: one of a class's vptrs past its start is a secondary one, and what
 * its constructors build there is the base subobject holding it, as a member couldn't. It goes over that vptr, then
 * gives it back to [owner], split around it as a base is ([BaseSplitter.splitBase]), where the member has a vptr
 * there; one known only from its constructors, which store the vptr as a plain field, keeps it whole.
 */
internal fun DiagnosticSink.placeMember(owner: Structure, at: Int, member: Structure) {
    if (member == owner) return
    val field = ClassNaming.fieldName(at)
    fun DataTypeComponent.isOwnVfptr(into: Structure) =
        into == owner && at > 0 && this.offset == at && fieldName == ClassUtils.VFPTR
    val vfptr = owner.definedComponents.firstOrNull { it.isOwnVfptr(owner) }?.dataType
    fun unplaced(into: Structure, why: List<DataTypeComponent>) = degradation(
        "member-unplaced",
        "${owner.name}::$field",
        "${member.name} overlaps ${why.joinToString { it.describe() }}" +
            " in ${into.name}".takeIf { into != owner }.orEmpty(),
    )
    var (into, offset) = owner.landing(at, member.length)
    // A struct holding its own fields alone takes the member over them, as its `<Class>_data` struct would.
    var ownData = owner.isFlatInferred()
    while (!ownData) {
        val range = offset.withLength(member.length)
        val inWay = into.componentsOverlapping(range).filterNot { it.isAt(offset, member) || it.isOwnVfptr(into) }
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
        .onSuccess { laid ->
            debug("member-placed", "${member.name} at +$at in ${owner.name}")
            into.settleHolders()
            owner.settleHolders()
            if (vfptr != null && into == owner && member.holdsVfptrAt(0)) {
                BaseSplitter(DtmRegistry(owner.dataTypeManager), this)
                    .splitBase(owner, listOf(owner.name), at, laid, vfptr)
            }
        }
        .onFailure { degradation("member-unplaced", "${owner.name}::$field", it.message) }
}

/** Whether a `{vfptr}` starts at [at] in this struct, its own or one inherited through the base subobject there. */
fun Structure.holdsVfptrAt(at: Int): Boolean {
    val holder = takeIf { at in 0..<length }?.getComponentContaining(at) ?: return false
    if (holder.fieldName == ClassUtils.VFPTR) return holder.offset == at
    return holder.isBaseField() && (holder.dataType as? Structure)?.holdsVfptrAt(at - holder.offset) == true
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

/** Whether this ends where [struct] does: a zero-length one, an empty base's run, by starting there. */
private fun DataTypeComponent.endsAtEndOf(struct: Structure) =
    offset + length == if (struct.isZeroLength) 0 else struct.length

/**
 * Where [length] bytes at [at] in this class struct go first, and at what offset into it: past its end, into the run
 * of its own fields it ends in ([isOwnFields]), stretched to hold them, which each class deriving from it holds too;
 * else into this.
 */
private fun Structure.landing(at: Int, length: Int): Pair<Structure, Int> {
    settle()
    val tail = definedComponents.lastOrNull()?.takeIf { isOwnFields(it) && it.endsAtEndOf(this) }
    if (tail == null || at < tail.offset || at + length <= this.length) return this to at
    return stretch(tail, at.withLength(length)) to at - tail.offset
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
 * Whether this class struct holds only fields the class pass inferred, laid in it with no `<Class>_data` struct
 * around them since nothing else is there: no base, vptr, nor own data or fields run, and a field marked
 * [ClassNaming.INFERRED]. A struct another importer or the reverser filled has no such mark, and stays theirs.
 */
fun Structure.isFlatInferred(): Boolean {
    val parts = definedComponents
    return parts.any { it.comment == ClassNaming.INFERRED } && parts.none {
        it.isBaseField() || it.fieldName == ClassUtils.VFPTR || it.fieldName == ClassNaming.VBPTR ||
            isOwnData(it) || isOwnFields(it)
    }
}

/**
 * This class struct's own `<Class>_data` structs, by their offset into it: those it holds and, its fields split
 * around a deriving class's vptr ([VfptrModel.SPLIT_BASE]), those inside its own `_fields` runs. A struct holding
 * its own fields alone ([isFlatInferred]) is its own, whole, at 0.
 */
fun Structure.ownData(): List<Pair<Int, Structure>> {
    if (isFlatInferred()) return listOf(0 to this)
    return definedComponents.flatMap { part ->
        when {
            isOwnData(part) -> listOf(part.offset to part.dataType as Structure)

            isOwnFields(part) -> (part.dataType as Structure).definedComponents.filter { isOwnData(it) }
                .map { part.offset + it.offset to it.dataType as Structure }

            else -> emptyList()
        }
    }
}

/** The bytes from [offset] to the next defined component or the end. */
fun Structure.roomAt(offset: Int) =
    (definedComponents.map { it.offset }.filter { it > offset }.minOrNull() ?: length) - offset

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

/** A base's `_fields` run ([BaseSplitter]): `<Base>_fields_<from>_<to>`, filed beside the base. */
private val BASE_RUN = Regex("(.+)${ClassNaming.FIELDS}_(\\d+)_(\\d+)")

/**
 * Grows each of [structs], class structs, to hold its bases whole, a base before the classes deriving from it. A
 * member laid past a base's end goes into the base's own tail run ([placeMember]), which each deriving class holds
 * and grows with. But where that run is zero-length, an empty base's, in a class that also ends in its own empty
 * run at the same offset, Ghidra cannot grow it there, and the class would stay as short as it was.
 */
fun DataTypeManager.growToHoldBases(structs: Collection<Structure>) {
    val done = mutableSetOf<Structure>()
    fun grow(struct: Structure) {
        if (!done.add(struct)) return
        val end = struct.definedComponents.filter { it.isBaseField() }.mapNotNull { part ->
            val run = part.dataType as? Structure ?: return@mapNotNull null
            val match = BASE_RUN.matchEntire(run.name)?.takeIf { it.groupValues[1] == run.categoryPath.name }
                ?: return@mapNotNull null
            val base = getDataType(run.categoryPath, match.groupValues[1]) as? Structure ?: return@mapNotNull null
            grow(base)
            part.offset - match.groupValues[2].toInt() + base.length
        }.maxOrNull() ?: return
        if (end > struct.length && !struct.isPackingEnabled) struct.growStructure(end - struct.length)
    }
    structs.forEach(::grow)
}

/**
 * Settles each struct holding this one ([settle]), and on up through those that grew, or are packed and so grew
 * with it. Ghidra grows a field whose type grew only over the undefined bytes after it, and a zero-length one, an
 * empty base's run, not at all.
 */
fun Structure.settleHolders(seen: MutableSet<Structure> = mutableSetOf()) {
    if (!seen.add(this)) return
    for (holder in parents.filterIsInstance<Structure>()) {
        if (holder.isPackingEnabled || holder.settle()) holder.settleHolders(seen)
    }
}

/**
 * Lays each field of this unpacked struct that is shorter than its type, a run that grew after it was laid, at its
 * type's length again, the empty runs that start where it ends moved on to its new end: the runs of a class's own
 * fields after its bases'. Where something else is in the way the field stays as it is. Whether anything moved.
 */
fun Structure.settle(): Boolean {
    if (isPackingEnabled) return false
    fun DataTypeComponent.move() = componentsOverlapping(offset.withLength(dataType.length)).none {
        it.ordinal != ordinal
    } && runCatching {
        val after = definedComponents.filter { c ->
            c.ordinal > ordinal && c.offset == offset + length && c.length == 0 &&
                (c.dataType as? Structure)?.isZeroLength == true
        }
        for (it in (after + this).sortedByDescending { it.ordinal }) {
            clearComponent(it.ordinal)
        }
        lay(offset, dataType, fieldName, comment)
        for (it in after) {
            insertAtOffset(offset + dataType.length, it.dataType, 0, it.fieldName, it.comment)
        }
    }.isSuccess

    val stuck = mutableSetOf<Int>()
    var moved = false
    while (true) {
        definedComponents.firstOrNull { c ->
            c.ordinal !in stuck && (c.dataType as? Structure)?.let { !it.isZeroLength && c.length < it.length } == true
        }?.run { if (move()) moved = true else stuck += ordinal } ?: return moved
    }
}
