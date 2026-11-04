package ghistabs.cpp.gui

import ghidra.program.model.data.DataTypeComponent
import ghidra.program.model.data.Structure
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghistabs.cpp.Access
import ghistabs.cpp.ClassHierarchyRecords
import ghistabs.cpp.ClassHierarchyRecords.Companion.writeClassEdit
import ghistabs.cpp.ClassNaming
import ghistabs.cpp.MemberAttrs.Companion.memberAttrs
import ghistabs.cpp.gui.ClassHierarchy.*

/**
 * A change to [owner]'s bases that a drag in the Class Hierarchy window asks for: drop [removed] and
 * add [added], either one alone. Both at once is a move within one class: the new clause takes the old
 * one's place in the base list.
 */
internal data class BaseEdit(val owner: ClassInfo, val removed: BaseRef?, val added: ClassInfo?)

/**
 * The edits dropping a class's node onto [dest] asks for: the class becomes [dest]'s child, under which
 * it then shows. Normally a node's children are its bases, [inverted] the classes derived from it.
 * [dragged] is the class, [edge] the clause that put its node where it was (none for a class filed under
 * its namespace), [parent] the class above it then, and [dest] null for the tree's root or a namespace.
 * Moving, the old clause goes; copying, it stays. Empty, with [reason] told, when the drop can't be.
 */
internal fun ClassHierarchy.planDrop(
    dragged: ClassInfo,
    edge: BaseRef?,
    parent: ClassInfo?,
    dest: ClassInfo?,
    inverted: Boolean,
    move: Boolean,
    reason: (String) -> Unit = {},
): List<BaseEdit> {
    fun no(why: String) = emptyList<BaseEdit>().also { reason(why) }

    // Normally the clause is the parent's, naming the dragged class; inverted, the dragged class's own.
    val removedFrom = (if (inverted) dragged else parent)?.takeIf { edge != null && move }
    if (dest == null) {
        removedFrom ?: return no("${dragged.qualifiedName} has no base here to remove")
        return listOf(BaseEdit(removedFrom, edge, null))
    }
    val (owner, base) = if (inverted) dragged to dest else dest to dragged
    val replaced = edge.takeIf { removedFrom?.id == owner.id }
    return when {
        owner.origin == Origin.IMPORTED -> no("${owner.qualifiedName} is only imported")

        owner.id == base.id -> no("a class can't be its own base")

        derivesFrom(base, owner) ->
            no("${base.qualifiedName} derives from ${owner.qualifiedName}: drop it on the root or a common base first")

        owner.bases.any { it.targetId == base.id && it != replaced } ->
            no("${owner.qualifiedName} already derives from ${base.qualifiedName}")

        // From one class's bases to another's: two edits, the removal first.
        else -> listOfNotNull(
            removedFrom?.takeIf { it.id != owner.id }?.let { BaseEdit(it, edge, null) },
            BaseEdit(owner, replaced, base),
        )
    }
}

/** Whether [cls] is [ancestor] or derives from it, through the bases the program has classes for. */
internal fun ClassHierarchy.derivesFrom(cls: ClassInfo, ancestor: ClassInfo): Boolean {
    val seen = mutableSetOf<Long>()
    val todo = ArrayDeque(listOf(cls))
    while (todo.isNotEmpty()) {
        val c = todo.removeFirst()
        if (c.id == ancestor.id) return true
        if (seen.add(c.id)) c.bases.mapNotNull(::get).forEach(todo::add)
    }
    return false
}

/** What a class's bases come from when that is worth a warning before changing them: null if nothing solid. */
internal fun ClassInfo.solidSource(): String? = when (origin) {
    Origin.STABS -> "the stabs"
    Origin.MSVC_RTTI -> "its MSVC RTTI"
    Origin.ITANIUM_RTTI, Origin.SWEPT_RTTI -> "its typeinfo"
    else -> null
}

/** What ties [member] to its class when that is worth a warning before moving it: null if nothing does. */
internal fun Program.memberSource(member: Member): String? {
    val at = addressFactory.getAddress(member.address)
    return when {
        at != null && memberAttrs(at) != null -> "the stabs"

        at != null && symbolTable.getSymbols(at).any { it.name.startsWith("_Z") || it.name.startsWith("?") } ->
            "its mangled name"

        else -> null
    }
}

/**
 * Sets [owner]'s bases to [bases], by hand ([ClassHierarchyRecords.EDITS]): the class then shows these
 * whatever its stabs or typeinfo say.
 */
internal fun Program.setBases(owner: ClassInfo, bases: List<BaseRef>) {
    val entries = bases.map {
        ClassHierarchyRecords.Base(
            it.targetId,
            it.name.takeIf { _ -> it.targetId == null },
            it.isVirtual,
            it.access ?: Access.PUBLIC,
            it.offset,
        )
    }
    writeClassEdit(owner.id, ClassHierarchyRecords.Entry(owner.structId, entries))
}

/** [edit] applied to its owner's bases, [added] spelled as [clause] gives it. */
internal fun BaseEdit.bases(clause: BaseRef?): List<BaseRef> {
    val kept = owner.bases.toMutableList()
    val at = removed?.let(kept::indexOf)?.takeIf { it >= 0 }
    at?.let(kept::removeAt)
    if (clause != null) kept.add(at ?: kept.size, clause)
    return kept
}

/** What [base] takes up embedded in a deriving class: its self-base, else its struct. Null for an empty one. */
internal fun Program.embeddingOf(base: ClassInfo): Structure? {
    val struct = base.structId?.let(dataTypeManager::getDataType) as? Structure ?: return null
    return (ClassUtils.getSelfBaseType(struct) as? Structure ?: struct).takeUnless { it.isZeroLength }
}

/** [cls]'s struct, if it has one to place a base in. */
internal fun Program.structOf(cls: ClassInfo): Structure? =
    cls.structId?.let(dataTypeManager::getDataType) as? Structure

/** The fields of [cls]'s struct that [base] placed at [offset] would overwrite. */
internal fun Program.overwrittenBy(cls: ClassInfo, base: ClassInfo, offset: Int): List<DataTypeComponent> {
    val struct = structOf(cls) ?: return emptyList()
    val part = embeddingOf(base) ?: return emptyList()
    val end = offset + part.length
    return struct.definedComponents.filter { it.offset < end && it.offset + it.length > offset }
        .filterNot { it.offset == offset && it.dataType.isEquivalent(part) }
}

/**
 * Embeds [base] in [cls]'s struct at [offset], over whatever is there, growing the struct to hold it.
 * Named as the import names a base field: `_base_` alone while the class has one base, else
 * `_base_<Base>` (`_vbase_` for a virtual one), and a lone `_base_` already there takes its type's name
 * once [baseCount] makes it one of several. Returns why it couldn't, or null.
 */
internal fun Program.placeBase(
    cls: ClassInfo,
    base: ClassInfo,
    offset: Int,
    isVirtual: Boolean,
    baseCount: Int,
): String? {
    val struct = structOf(cls) ?: return "${cls.qualifiedName} has no struct"
    val part = embeddingOf(base) ?: return "${base.qualifiedName} has no struct with data"
    if (struct.isPackingEnabled) return "${struct.name} is packed, so its fields have no fixed offsets"
    if (baseCount > 1) {
        struct.definedComponents.filter {
            it.fieldName == ClassNaming.BASE_PREFIX || it.fieldName == ClassNaming.VBASE_PREFIX
        }.forEach { it.fieldName += it.dataType.name.substringBefore(ClassNaming.FIELDS + "_") }
    }
    val end = offset + part.length
    if (end > struct.length) struct.growStructure(end - struct.length)
    struct.definedComponents.filter { it.offset < end && it.offset + it.length > offset }
        .sortedByDescending { it.offset }.forEach { struct.clearAtOffset(it.offset) }
    val name = ClassNaming.baseFieldName(isVirtual, base.name, baseCount)
    val comment = (if (isVirtual) "virtual " else "") + "base, placed by hand"
    struct.replaceAtOffset(offset, part, part.length, name, comment)
    return null
}

/** Moves [member]'s symbol into [target]'s namespace. Throws what Ghidra does (a name taken there). */
internal fun Program.moveMember(member: Member, target: ClassInfo) {
    val ns =
        symbolTable.getSymbol(target.id)?.`object` as? Namespace ?: error("no namespace for ${target.qualifiedName}")
    val sym = member.symbolId?.let(symbolTable::getSymbol) ?: error("no symbol for ${member.name}")
    sym.setNameAndNamespace(sym.name, ns, sym.source.takeUnless { it == SourceType.DEFAULT } ?: SourceType.USER_DEFINED)
}
