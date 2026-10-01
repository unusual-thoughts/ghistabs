package ghistabs.hierarchy

import docking.widgets.tree.GTreeLazyNode
import docking.widgets.tree.GTreeNode
import generic.theme.GIcon
import ghistabs.hierarchy.ClassHierarchy.ClassInfo
import ghistabs.hierarchy.ClassHierarchy.Origin
import ghistabs.parse.Access
import resources.ResourceManager
import javax.swing.Icon

/*
 * The tree astrelsky's Ghidra-Cpp-Class-Analyzer docks as its "ClassTypeInfo Tree": classes filed under
 * their namespaces, and each class's children its direct bases, which expand into theirs in turn, then
 * the classes nested in it. Read-only, and over [ClassHierarchy] instead of a typeinfo database.
 */

internal val CLASS_ICON: Icon = GIcon("icon.plugin.symboltree.node.class")
private val SWEPT_ICON: Icon = ResourceManager.getDisabledIcon(CLASS_ICON)
private val NAMESPACE_ICON: Icon = GIcon("icon.plugin.symboltree.node.namespace")

/** The program's classes, filed by namespace. */
class ClassHierarchyRootNode(private val programName: String, hierarchy: ClassHierarchy) : GTreeNode() {
    init {
        val classNodes = hierarchy.classes.associate { it.path to ClassNode(it) }
        val folders = mutableMapOf<List<String>, NamespaceNode>()
        val children = mutableMapOf<List<String>, MutableList<GTreeNode>>()

        // A namespace that is a class files what it holds as the class's nested classes.
        fun ensure(path: List<String>) {
            if (path.isEmpty() || path in classNodes || path in folders) return
            folders[path] = NamespaceNode(path.last())
            ensure(path.dropLast(1))
            children.getOrPut(path.dropLast(1)) { mutableListOf() } += folders.getValue(path)
        }
        for ((path, node) in classNodes) {
            ensure(path.dropLast(1))
            children.getOrPut(path.dropLast(1)) { mutableListOf() } += node
        }
        for ((path, kids) in children) {
            val sorted = kids.sortedWith(NODE_ORDER)
            when (val container = classNodes[path]) {
                null -> (folders[path] ?: this).setChildren(sorted)
                else -> container.nested += sorted
            }
        }
    }

    override fun getName() = programName
    override fun getIcon(expanded: Boolean) = NAMESPACE_ICON
    override fun getToolTip(): String? = null
    override fun isLeaf() = false
}

/** A namespace that is not itself a class. */
class NamespaceNode(private val name: String) : GTreeNode() {
    override fun getName() = name
    override fun getIcon(expanded: Boolean) = NAMESPACE_ICON
    override fun getToolTip(): String? = null
    override fun isLeaf() = false
}

/**
 * A class: [info] filed under its namespace, or a [base] of the class above it, spelled the way the
 * base clause does (`virtual protected Foo`). A base the program has no class for is a leaf.
 */
class ClassNode private constructor(val info: ClassInfo?, val base: ClassHierarchy.BaseRef?) : GTreeLazyNode() {
    constructor(info: ClassInfo) : this(info, null)

    /** Classes declared inside this one; only a class filed under its namespace has them. */
    internal val nested = mutableListOf<GTreeNode>()

    private fun basesOf() = info?.bases.orEmpty()

    override fun generateChildren(): List<GTreeNode> = basesOf().map { ClassNode(it.target, it) } + nested

    override fun getName(): String = base?.let { b ->
        buildString {
            if (b.isVirtual) append("virtual ")
            if (b.access != null && b.access != Access.PUBLIC) append(b.access.name.lowercase()).append(' ')
            append(b.name)
        }
    } ?: info!!.name

    override fun getIcon(expanded: Boolean): Icon = when (info?.origin) {
        Origin.STABS -> CLASS_ICON
        else -> SWEPT_ICON
    }

    override fun getToolTip(): String = buildString {
        append("<html>")
        append(escape(info?.qualifiedName ?: base?.name.orEmpty()))
        val origin = when (info?.origin) {
            Origin.STABS -> "bases from the stabs"
            Origin.SWEPT_RTTI -> "no stabs: vtable swept, bases from its typeinfo"
            Origin.SWEPT -> "no stabs: vtable swept, bases unknown"
            null -> "no class built for it: a plain struct, or only declared"
        }
        append("<br>").append(origin)
        if (info?.isAbstract == true) append("<br>abstract")
        info?.vftable?.let { append("<br>vftable at ").append(it) }
        if (info?.vftable == null) info?.typeinfo?.let { append("<br>typeinfo at ").append(it) }
    }

    override fun isLeaf() = basesOf().isEmpty() && nested.isEmpty()

    // Two bases of one class can share a name (a direct and an indirect `Base`); never merge them.
    override fun equals(other: Any?) = this === other
    override fun hashCode() = System.identityHashCode(this)
}

private fun escape(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

/** Namespaces before classes, then by name, as upstream sorts them. */
private val NODE_ORDER = compareBy<GTreeNode>({ it is ClassNode }, { it.name.lowercase() }, { it.name })
