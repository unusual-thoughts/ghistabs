package ghicpp.hierarchy

import ghicpp.Access
import ghicpp.ClassHierarchyRecords
import ghicpp.ClassHierarchyRecords.Companion.readClassRecord
import ghicpp.ClassHierarchyRecords.Companion.writeClassEdit
import ghicpp.ClassNaming
import ghicpp.MemberAttrs.Companion.memberAttrs
import ghicpp.hierarchy.ClassHierarchy.*
import ghicpp.recover.updateFieldTypes
import ghidra.program.model.data.*
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.VariableUtilities
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.SymbolType
import ghidra.util.task.TaskMonitor
import ghistabs.*

sealed interface Drop {
    data class MoveBase(val detach: BaseEdit?, val attach: BaseEdit? = null) : Drop
    data class Illegal(val reason: String) : Drop

    // From one class's bases to another's: two edits, the removal first.
    val edits get() = (this as? MoveBase)?.run { listOfNotNull(detach, attach) }.orEmpty()
    val error get() = (this as? Illegal)?.reason
}

/** Why the namespace at [from] can't move under the one at [to], or null when it can. */
internal fun checkNamespaceMove(from: List<String>, to: List<String>): String? = when {
    to == from.dropLast(1) -> "${from.joinToString("::")} is already there"
    to.startsWith(from) -> "a namespace can't move into itself"
    else -> null
}

/**
 * A change to [of]'s bases that a drag in the Class Hierarchy window asks for: drop [removed] and
 * add [added], either one alone. Both at once is a move within one class: the new clause takes the old
 * one's place in the base list.
 */
data class BaseEdit(val of: ClassView, val removed: BaseRef?, val added: ClassView? = null)

/** An edit of [owner]'s base clause [edge] that keeps its base, to spell it anew; null for a base with no class. */
internal fun ClassHierarchy.reclause(owner: ClassView, edge: BaseRef): BaseEdit? =
    this[edge]?.takeIf { owner.origin != Origin.LIBRARY && edge in owner.bases }?.let { BaseEdit(owner, edge, it) }

/** Whether this keeps the base it removes, only spelling its clause anew. */
internal val BaseEdit.isReclause get() = added != null && removed?.targetId == added.id

/**
 * The edits a drop in the Class Hierarchy window asks for: [owner] gains [base], and [removedFrom] loses
 * [edge], the clause that put the dropped node where it was. [removedFrom] is null when copying or when
 * the node was filed under its namespace; it is [owner] itself when the clause moves within one class,
 * where the new base takes the old one's place. [base] null (a drop on the root or a namespace) only
 * removes, and [owner] then just names the dragged class.
 */
internal fun ClassHierarchy.planDrop(
    owner: ClassView,
    base: ClassView?,
    removedFrom: ClassView?,
    edge: BaseRef?,
): Drop {
    val replaced = edge.takeIf { removedFrom?.id == owner.id }
    return when {
        base == null && removedFrom != null -> Drop.MoveBase(BaseEdit(removedFrom, edge))

        base == null -> Drop.Illegal("${owner.qualifiedName} has no base here to remove")

        owner.origin == Origin.LIBRARY -> Drop.Illegal("${owner.qualifiedName} is only imported")

        owner.id == base.id -> Drop.Illegal("a class can't be its own base")

        derivesFrom(base, owner) -> Drop.Illegal(
            "${base.qualifiedName} derives from ${owner.qualifiedName}: drop it on the root or a common base first",
        )

        owner.bases.any { it.targetId == base.id && it != replaced } ->
            Drop.Illegal("${owner.qualifiedName} already derives from ${base.qualifiedName}")

        else -> Drop.MoveBase(
            removedFrom?.takeIf { it.id != owner.id }?.let { BaseEdit(it, edge) },
            BaseEdit(owner, replaced, base),
        )
    }
}

/** Whether [cls] is [ancestor] or derives from it, through the bases the program has classes for. */
internal fun ClassHierarchy.derivesFrom(cls: ClassView, ancestor: ClassView): Boolean {
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
internal fun ClassView.solidSource(): String? =
    origin.desc.removePrefix("from ").takeIf { origin.baseSource == SourceType.IMPORTED }

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
internal fun Program.setBases(owner: ClassView, bases: List<BaseRef>) {
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
    val kept = of.bases.toMutableList()
    val at = removed?.let(kept::indexOf)?.takeIf { it >= 0 }
    at?.let(kept::removeAt)
    if (clause != null) kept.add(at ?: kept.size, clause)
    return kept
}

/** What [base] takes up embedded in a deriving class: its self-base, else its struct. Null for an empty one. */
internal fun Program.embeddingOf(base: ClassView): Structure? {
    val struct = base.structId?.let(dataTypeManager::getDataType) as? Structure ?: return null
    // Where ClassUtils.getSelfBaseType (11.1+) looks: the self-base sits at its base-class path.
    val selfBase = dataTypeManager.getDataType(ClassUtils.getBaseClassDataTypePath(struct)) as? Structure
    return (selfBase ?: struct).takeUnless { it.isZeroLength }
}

/** [cls]'s struct, if it has one to place a base in. */
internal fun Program.structOf(cls: ClassView): Structure? =
    cls.structId?.let(dataTypeManager::getDataType) as? Structure

/** The fields of [cls]'s struct that [base] placed at [offset] would overwrite. */
internal fun Program.overwrittenBy(cls: ClassView, base: ClassView, offset: Int): List<DataTypeComponent> {
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
    cls: ClassView,
    base: ClassView,
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

/**
 * Renames the field of [cls]'s struct holding [base] for its new virtuality, leaving the layout as it is:
 * the field the base's struct or self-base takes, or, split around the class's own vfptr, its
 * `<Base>_fields_…` run. False when no field holds it.
 */
internal fun Program.respellBase(cls: ClassView, base: ClassView, isVirtual: Boolean, baseCount: Int): Boolean {
    val struct = structOf(cls) ?: return false
    val part = embeddingOf(base)
    val runs = base.name + ClassNaming.FIELDS + "_"
    val field = struct.definedComponents.firstOrNull {
        (part != null && it.dataType.isEquivalent(part)) || it.dataType.name.startsWith(runs)
    } ?: return false
    field.fieldName = ClassNaming.baseFieldName(isVirtual, base.name, baseCount)
    return true
}

/** Moves [member]'s symbol into [target]'s namespace. Throws what Ghidra does (a name taken there). */
internal fun Program.moveMember(member: Member, target: ClassView) {
    val ns = resolve(target) ?: error("no namespace for ${target.qualifiedName}")
    val sym = member.symbolId?.let(symbolTable::getSymbol) ?: error("no symbol for ${member.name}")
    sym.setNameAndNamespace(sym.name, ns, sym.source.takeUnless { it == SourceType.DEFAULT } ?: SourceType.USER_DEFINED)
}

fun Program.resolve(cls: ClassView) = symbolTable.getSymbol(cls.id)?.`object` as? GhidraClass

/** The functions [ns] holds, its thunks and imports aside. */
internal fun Program.methodsOf(ns: GhidraClass): List<Function> = symbolTable.getSymbols(ns)
    .filter { it.symbolType == SymbolType.FUNCTION && !it.isExternal }
    .mapNotNull { functionManager.getFunctionAt(it.address)?.takeUnless(Function::isThunk) }

/** The function at [m]'s address, when it is a function member. */
internal fun Program.functionOf(m: Member): Function? = m.takeIf { it.kind == MemberKind.FUNCTION }
    ?.let { addressFactory.getAddress(it.address) }
    ?.let(functionManager::getFunctionAt)

/**
 * Retypes [cls]'s own fields off what [methods] load and store through `this`, or off all of [methodsOf] its
 * namespace's when null.
 */
internal fun Program.updateFieldTypes(cls: ClassView, methods: List<Function>?, monitor: TaskMonitor) {
    val ns = resolve(cls) ?: return
    updateFieldTypes(ns, methods ?: methodsOf(ns), monitor)
}

/**
 * The definitions laid vftables type [func]'s slots with: a slot pointing at it or at a thunk to it. The class
 * pass gives each function one, shared by every table holding it.
 */
internal fun Program.slotDefinitionsOf(func: Function): Set<FunctionDefinition> =
    (listOf(func.entryPoint) + func.getFunctionThunkAddresses(false).orEmpty()).asSequence()
        .flatMap { referenceManager.getReferencesTo(it).iterator().asSequence() }
        .mapNotNull { ref ->
            val table = listing.getDataContaining(ref.fromAddress)?.takeIf { it.dataType is Structure }
            val slot = table?.getPrimitiveAt(ref.fromAddress.subtract(table.address).toInt())
            (slot?.dataType as? Pointer)?.dataType as? FunctionDefinition
        }
        .toSet()

/**
 * Copies [func]'s signature into each of its [slotDefinitionsOf], as `ApplyClassFunctionSignatureUpdatesScript`
 * does for a whole class: every vftable holding it then calls it so. A definition keeps its name. How many
 * it changed.
 */
internal fun Program.applySignatureToSlots(func: Function): Int {
    val defs = slotDefinitionsOf(func)
    for (def in defs) {
        def.replaceWith(
            FunctionDefinitionDataType(def.categoryPath, def.name, func.signature, dataTypeManager),
        )
    }
    return defs.size
}

/**
 * Rename [cls] to [newName] in [program], and everything spelled after it:
 *
 * - its namespace, which the class record and member attributes key by id, not name;
 * - its constructors and destructors (`Old`, `~Old`, every variant);
 * - its struct, its self-base (`…/Old/!internal/Old`) and their `Old_fields_…` runs, and each
 *   category whose trailing path is the class's (`/ClassDataTypes/…/Old`, a DWARF or Ghidra `…/Old`),
 *   so the vftable structs and nested classes' types follow it;
 * - its own fields' `Old_data…` structs and the fields holding them;
 * - its vftable structs (`Old_vftable…`), and its derived classes' `vftable_for_Old` labels, their
 *   `…_vftable_for_Old` structs and `_base_Old` / `_vbase_Old` fields.
 *
 * Throws what renaming the namespace throws (a bad or taken name), before anything changes. Anything
 * else that can't take its new name (a datatype already so named) keeps the old one, and is listed in
 * what this returns.
 */
internal fun Program.renameClass(hierarchy: ClassHierarchy, cls: ClassView, newName: String): List<String> {
    val ns = resolve(cls) ?: return listOf("no class namespace")
    val old = ns.name
    if (newName == old) return emptyList()
    val skipped = mutableListOf<String>()
    fun attempt(what: String, rename: () -> Unit) {
        runCatching(rename).onFailure { skipped += "$what: ${it.message}" }
    }

    val structors = setOf(old, "~$old")
    val struct = cls.structId?.let(dataTypeManager::getDataType) as? Structure
    // Its "self-base", `…/Old/!internal/Old`: its category follows the rename, its name doesn't.
    val selfBase = struct?.let { dataTypeManager.getDataType(ClassUtils.getBaseClassDataTypePath(it)) }
    // The namespace, and the categories filed by its path (`/ClassDataTypes/…/Old`, `…/Old/!internal`).
    skipped += relocateNamespace(ns, ns.parentNamespace, newName)
    for (sym in symbolTable.getSymbols(ns).filter { it.name in structors }) {
        attempt(sym.name) { sym.setName(sym.name.replaceFirst(old, newName), SourceType.USER_DEFINED) }
    }

    struct?.let { attempt(it.pathName) { it.name = newName } }
    selfBase?.let { attempt(it.pathName) { it.name = newName } }
    // A split base's field runs, `Old_fields_<from>_<until>`, beside the struct and the self-base.
    val fieldsPrefix = old + ClassNaming.FIELDS + "_"
    listOfNotNull(struct, selfBase).mapNotNull { dataTypeManager.getCategory(it.categoryPath) }.distinct()
        .flatMap { it.dataTypes.filter { dt -> dt.name.startsWith(fieldsPrefix) } }
        .forEach { dt -> attempt(dt.pathName) { dt.name = newName + dt.name.removePrefix(old) } }

    renameData(ns, struct, old, newName, ::attempt)

    // Old_vftable, Old_vftable_for_Base, Old_vftable1: in the (renamed) class's category.
    val vftablePrefix = ClassNaming.vftableName(old)
    dataTypeManager.getCategory(ClassNaming.vftableCategory(ns))?.dataTypes.orEmpty()
        .filter { it.name.startsWith(vftablePrefix) }
        .forEach { dt ->
            attempt(dt.pathName) {
                dt.name = ClassNaming.vftableName(newName) + dt.name.removePrefix(vftablePrefix)
            }
        }

    // What derived classes name after it.
    for (d in hierarchy.derivedOf(cls).map { it.cls }) renameInDerived(d, old, newName, ::attempt)
    return skipped
}

/**
 * Renames [old]'s own fields' structs, `Old_data` and `Old_data_1`…, in its (renamed) class's category,
 * and the fields of its [struct] holding them, which share their names.
 */
private fun Program.renameData(
    ns: Namespace,
    struct: Structure?,
    old: String,
    newName: String,
    attempt: (String, () -> Unit) -> Unit,
) {
    val dataName = old + ClassNaming.DATA
    fun isData(name: String?) = name == dataName || name?.startsWith(dataName + "_") == true
    dataTypeManager.getCategory(ClassNaming.vftableCategory(ns))?.dataTypes.orEmpty()
        .filter { isData(it.name) }
        .forEach { dt -> attempt(dt.pathName) { dt.name = newName + dt.name.removePrefix(old) } }
    struct?.definedComponents.orEmpty().filter { isData(it.fieldName) }.forEach { c ->
        attempt("${struct?.pathName}.${c.fieldName}") { c.fieldName = newName + c.fieldName.removePrefix(old) }
    }
}

/**
 * In derived class [d], rename what is named after its base [old]: `vftable_for_Old` labels and structs,
 * `_base_Old` and `_vbase_Old` fields.
 */
private fun Program.renameInDerived(
    d: ClassView,
    old: String,
    newName: String,
    attempt: (String, () -> Unit) -> Unit,
) {
    val dns = resolve(d) ?: return
    symbolTable.getSymbols(ClassNaming.vftableForLabel(old), dns).forEach { sym ->
        attempt(sym.name) { sym.setName(ClassNaming.vftableForLabel(newName), SourceType.USER_DEFINED) }
    }
    dataTypeManager.getCategory(ClassNaming.vftableCategory(dns))?.dataTypes.orEmpty()
        .filter { it.name.endsWith(ClassNaming.FOR_INFIX + old) }
        .forEach { dt -> attempt(dt.pathName) { dt.name = dt.name.removeSuffix(old) + newName } }
    val dStruct = d.structId?.let(dataTypeManager::getDataType) as? Structure ?: return
    for (c in dStruct.definedComponents) {
        val prefix = listOf(ClassNaming.BASE_PREFIX, ClassNaming.VBASE_PREFIX).firstOrNull { c.fieldName == it + old }
            ?: continue
        attempt("${dStruct.pathName}.${c.fieldName}") { c.fieldName = prefix + newName }
    }
}

/**
 * Moves [ns] under [newParent] as [newName], and what is filed by its path with it. Ghidra finds a
 * class's data by namespace path: its vftables under `/ClassDataTypes/<path>/`, DWARF's types under
 * `/DWARF/<path>/`, a class's own category (self-base, field runs) at `<struct category>/<Class>/`,
 * and its struct in a category ending with its parent namespace's path
 * (`DataTypeUtilities.findExistingClassStruct`, which types `this`). So every category ending in the
 * old path moves to the new one, and each class's struct that no longer sits where Ghidra looks for
 * it moves to where it does.
 *
 * Throws what moving or renaming the namespace throws (a name taken there, a namespace into itself),
 * before anything changes. Anything else that can't move keeps its place, and is listed in what this
 * returns.
 */
internal fun Program.relocateNamespace(ns: Namespace, newParent: Namespace, newName: String = ns.name): List<String> {
    val oldPath = ns.path
    // Each class at or under it, with its struct and its path now.
    val classes = (sequenceOf(ns) + ns.nestedNamespaces()).filterIsInstance<GhidraClass>()
        .map { it to structOf(it) }.toList()
    val oldPaths = classes.associate { (c, _) -> c.id to c.path }

    if (ns.parentNamespace != newParent) ns.parentNamespace = newParent
    if (ns.name != newName) ns.symbol.setName(newName, SourceType.USER_DEFINED)
    val newPath = ns.path
    if (newPath == oldPath) return emptyList()

    val skipped = mutableListOf<String>()
    fun attempt(what: String, change: () -> Unit) {
        runCatching(change).onFailure { skipped += "$what: ${it.message}" }
    }
    relocateCategories(oldPath, newPath, ::attempt)
    for ((cls, struct) in classes) {
        struct ?: continue
        val oldParent = oldPaths.getValue(cls.id).dropLast(1)
        val newParentPath = cls.path.dropLast(1)
        val elements = struct.categoryPath.pathElements.toList()
        if (newParentPath.isEmpty() || elements.endsWith(newParentPath)) continue
        val base = if (elements.endsWith(oldParent)) elements.dropLast(oldParent.size) else elements
        val target = (base + newParentPath).toCategoryPath()
        attempt(struct.pathName) { struct.categoryPath = target }
    }
    return skipped
}

/**
 * Moves each category whose path ends with [oldPath] to end with [newPath] instead, deepest first.
 * A category whose path ends with a longer namespace path than [oldPath] is that other namespace's
 * (`/ClassDataTypes/other/Foo` for `other::Foo`, when `Foo` moves), and stays.
 */
private fun Program.relocateCategories(
    oldPath: List<String>,
    newPath: List<String>,
    attempt: (String, () -> Unit) -> Unit,
) {
    val matching = dataTypeManager.rootCategory.descendants().filter { c ->
        val elements = c.categoryPath.pathElements.toList()
        elements.endsWith(oldPath) && !isLongerNamespacePath(elements, oldPath.size)
    }.sortedByDescending { it.categoryPath.pathElements.size }.toList()
    for (category in matching) {
        val elements = category.categoryPath.pathElements.toList()
        val prefix = elements.dropLast(oldPath.size)
        attempt(category.categoryPathName) { moveCategory(category, prefix + newPath) }
    }
}

// Whether the category path's last [size] + 1 or more elements name a namespace the program has.
private fun Program.isLongerNamespacePath(elements: List<String>, size: Int) =
    (size + 1..elements.size).any { n -> namespaceAt(elements.takeLast(n))?.isGlobal == false }

private fun Program.moveCategory(category: Category, to: List<String>) {
    val target = to.toCategoryPath()
    if (target.parent != category.categoryPath.parent) {
        val parent = dataTypeManager.createCategory(target.parent)
        parent.moveCategory(category, TaskMonitor.DUMMY)
    }
    if (category.name != target.name) category.name = target.name
}

private fun Program.structOf(cls: GhidraClass): Structure? =
    readClassRecord().orEmpty()[cls.id]?.structId?.let(dataTypeManager::getDataType) as? Structure
        ?: VariableUtilities.findExistingClassStruct(cls, dataTypeManager)

private fun Namespace.nestedNamespaces(): Sequence<Namespace> =
    symbol.program.symbolTable.getChildren(symbol).iterator().asSequence()
        .mapNotNull { it.`object` as? Namespace }
        .flatMap { sequenceOf(it) + it.nestedNamespaces() }
