package ghistabs.cpp.gui

import ghidra.program.model.data.Category
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.VariableUtilities
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.ClassHierarchyRecords.Companion.readClassEdits
import ghistabs.cpp.ClassHierarchyRecords.Companion.readClassRecord

/** The namespace at [path] (outermost first), the global one for an empty path; null if there is none. */
internal fun Program.namespaceAt(path: List<String>): Namespace? = path.fold(globalNamespace) { ns, name ->
    ns?.let { symbolTable.getNamespace(name, it) }
}

/** Why the namespace at [from] can't move under the one at [to], or null when it can. */
internal fun namespaceMoveRefusal(from: List<String>, to: List<String>): String? = when {
    to == from.dropLast(1) -> "${from.joinToString("::")} is already there"
    to.size >= from.size && to.subList(0, from.size) == from -> "a namespace can't move into itself"
    else -> null
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
    val oldPath = ns.getPathList(true).toList()
    // Each class at or under it, with its struct and its path now.
    val classes = (sequenceOf(ns) + ns.nestedNamespaces()).filterIsInstance<GhidraClass>()
        .map { it to structOf(it) }.toList()
    val oldPaths = classes.associate { (c, _) -> c.id to c.getPathList(true).toList() }

    if (ns.parentNamespace != newParent) ns.parentNamespace = newParent
    if (ns.name != newName) ns.symbol.setName(newName, SourceType.USER_DEFINED)
    val newPath = ns.getPathList(true).toList()
    if (newPath == oldPath) return emptyList()

    val skipped = mutableListOf<String>()
    fun attempt(what: String, change: () -> Unit) {
        runCatching(change).onFailure { skipped += "$what: ${it.message}" }
    }
    relocateCategories(oldPath, newPath, ::attempt)
    for ((cls, struct) in classes) {
        struct ?: continue
        val oldParent = oldPaths.getValue(cls.id).dropLast(1)
        val newParentPath = cls.getPathList(true).toList().dropLast(1)
        val elements = struct.categoryPath.pathElements.toList()
        if (newParentPath.isEmpty() || elements.endsWith(newParentPath)) continue
        val base = if (elements.endsWith(oldParent)) elements.dropLast(oldParent.size) else elements
        val target = (base + newParentPath).fold(CategoryPath.ROOT) { p, seg -> CategoryPath(p, seg) }
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
    val target = to.fold(CategoryPath.ROOT) { p, seg -> CategoryPath(p, seg) }
    if (target.parent != category.categoryPath.parent) {
        val parent = dataTypeManager.createCategory(target.parent)
        parent.moveCategory(category, TaskMonitor.DUMMY)
    }
    if (category.name != target.name) category.name = target.name
}

private fun Program.structOf(cls: GhidraClass): Structure? {
    val id = (readClassRecord().orEmpty()[cls.id] ?: readClassEdits()[cls.id])?.structId
    return id?.let(dataTypeManager::getDataType) as? Structure
        ?: VariableUtilities.findExistingClassStruct(cls, dataTypeManager)
}

private fun Namespace.nestedNamespaces(): Sequence<Namespace> {
    val children: Iterator<Symbol> = symbol.program.symbolTable.getChildren(symbol)
    return children.asSequence().mapNotNull { it.`object` as? Namespace }.flatMap {
        sequenceOf(it) + it.nestedNamespaces()
    }
}

internal fun Category.descendants(): Sequence<Category> =
    categories.asSequence().flatMap { sequenceOf(it) + it.descendants() }

internal fun List<String>.endsWith(tail: List<String>) = size >= tail.size && subList(size - tail.size, size) == tail
