package ghistabs.cpp.gui

import ghidra.program.model.data.Category
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghistabs.cpp.ClassNaming

/**
 * Rename [cls] to [newName] in [program], and everything spelled after it:
 *
 * - its namespace, which the class record and member attributes key by id, not name;
 * - its constructors and destructors (`Old`, `~Old`, every variant);
 * - its struct, and each category whose trailing path is the class's (`/ClassDataTypes/…/Old`, a
 *   DWARF or Ghidra `…/Old`), so the vftable structs and nested classes' types follow it;
 * - its vftable structs (`Old_vftable…`), and its derived classes' `vftable_for_Old` labels, their
 *   `…_vftable_for_Old` structs and `_base_Old` / `_vbase_Old` fields.
 *
 * Throws what renaming the namespace throws (a bad or taken name), before anything changes. Anything
 * else that can't take its new name (a datatype already so named) keeps the old one, and is listed in
 * what this returns.
 */
internal fun Program.renameClass(
    hierarchy: ClassHierarchy,
    cls: ClassHierarchy.ClassInfo,
    newName: String,
): List<String> {
    val ns = symbolTable.getSymbol(cls.id)?.`object` as? GhidraClass ?: return listOf("no class namespace")
    val old = ns.name
    if (newName == old) return emptyList()
    val skipped = mutableListOf<String>()
    fun attempt(what: String, rename: () -> Unit) {
        runCatching(rename).onFailure { skipped += "$what: ${it.message}" }
    }

    val structors = setOf(old, "~$old")
    val members = symbolTable.getSymbols(ns).filter { it.name in structors }
    ns.symbol.setName(newName, SourceType.USER_DEFINED)
    for (sym in members) {
        attempt(sym.name) { sym.setName(sym.name.replaceFirst(old, newName), SourceType.USER_DEFINED) }
    }

    val struct = cls.structId?.let(dataTypeManager::getDataType) as? Structure
    // Deepest first, so a nested class's category is renamed before the one holding it moves.
    val path = cls.path
    for (category in dataTypeManager.rootCategory.descendants().filter {
        it.categoryPath.pathElements.toList().endsWith(path)
    }.sortedByDescending { it.categoryPath.pathElements.size }) {
        attempt(category.categoryPathName) { category.name = newName }
    }
    struct?.let { attempt(it.pathName) { it.name = newName } }

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
 * In derived class [d], rename what is named after its base [old]: `vftable_for_Old` labels and structs,
 * `_base_Old` and `_vbase_Old` fields.
 */
private fun Program.renameInDerived(
    d: ClassHierarchy.ClassInfo,
    old: String,
    newName: String,
    attempt: (String, () -> Unit) -> Unit,
) {
    val dns = symbolTable.getSymbol(d.id)?.`object` as? GhidraClass ?: return
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

private fun Category.descendants(): Sequence<Category> =
    categories.asSequence().flatMap { sequenceOf(it) + it.descendants() }

private fun List<String>.endsWith(tail: List<String>) = size >= tail.size && subList(size - tail.size, size) == tail
