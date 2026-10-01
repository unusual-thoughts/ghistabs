package ghistabs.hierarchy

import docking.widgets.tree.GTreeLazyNode
import docking.widgets.tree.GTreeNode
import generic.theme.GIcon
import ghistabs.hierarchy.ClassHierarchy.ClassInfo
import ghistabs.hierarchy.ClassHierarchy.MemberKind
import ghistabs.hierarchy.ClassHierarchy.Origin
import ghistabs.parse.Access
import java.awt.image.BufferedImage
import javax.swing.Icon
import javax.swing.ImageIcon

/*
 * The tree astrelsky's Ghidra-Cpp-Class-Analyzer docks as its "ClassTypeInfo Tree": classes filed under
 * their namespaces, and each class's children its direct bases, which expand into theirs in turn, then
 * its functions and labels as the Symbol Tree shows them, then the classes nested in it. Read-only, and
 * over [ClassHierarchy] instead of a typeinfo database.
 */

internal val CLASS_ICON: Icon = GIcon("icon.plugin.symboltree.node.class")
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

                else -> {
                    sorted.filterIsInstance<ClassNode>().forEach { it.isNested = true }
                    container.nested += sorted
                }
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

    // Only the class filed under its namespace lists its members: under a base, they'd repeat.
    private fun membersOf() = if (base == null) info?.members.orEmpty() else emptyList()

    override fun generateChildren(): List<GTreeNode> =
        basesOf().map { ClassNode(it.target, it) } + membersOf().map(::MemberNode) + nested

    override fun getName(): String = base?.let { b ->
        buildString {
            if (b.isVirtual) append("virtual ")
            if (b.access != null && b.access != Access.PUBLIC) append(b.access.name.lowercase()).append(' ')
            append(b.name)
        }
    } ?: info!!.name

    /** Set on a class filed under the class it's declared in. */
    internal var isNested = false

    // SWEPT only for a class the sweep found: a base with no class at all stays a plain class.
    private val kind
        get() = when {
            isNested -> Kind.NESTED
            base?.isVirtual == true -> if (info?.isAbstract == true) Kind.VIRTUAL_ABSTRACT else Kind.VIRTUAL
            info?.isAbstract == true -> Kind.ABSTRACT
            info != null && info.origin != Origin.STABS -> Kind.SWEPT
            else -> Kind.NORMAL
        }

    override fun getIcon(expanded: Boolean): Icon = kind.icon

    override fun getToolTip(): String = buildString {
        append("<html>")
        append(escape(info?.qualifiedName ?: base?.name.orEmpty()))
        // The typedef shortening pass renamed its struct; the namespace keeps the long spelling.
        info?.struct?.name?.takeIf { it != info.name }?.let { append("<br>shortened: ").append(escape(it)) }
        val origin = when (info?.origin) {
            Origin.STABS -> "bases from the stabs"
            Origin.SWEPT_RTTI -> "no stabs: vtable swept, bases from its typeinfo"
            Origin.SWEPT -> "no stabs: vtable swept, bases unknown"
            null -> "no class built for it: a plain struct, or only declared"
        }
        append("<br>").append(origin)
        if (kind != Kind.NORMAL && kind != Kind.SWEPT) append("<br>").append(kind.label)
        info?.vftable?.let { append("<br>vftable at ").append(it) }
        if (info?.vftable == null) info?.typeinfo?.let { append("<br>typeinfo at ").append(it) }
    }

    override fun isLeaf() = basesOf().isEmpty() && membersOf().isEmpty() && nested.isEmpty()

    // Two bases of one class can share a name (a direct and an indirect `Base`); never merge them.
    override fun equals(other: Any?) = this === other
    override fun hashCode() = System.identityHashCode(this)
}

/** A function or label of the class above it. */
class MemberNode(val member: ClassHierarchy.Member) : GTreeNode() {
    override fun getName() = member.name
    override fun getIcon(expanded: Boolean): Icon = MEMBER_ICONS.getValue(member.kind)
    override fun getToolTip(): String = buildString {
        append("<html>").append(escape(member.signature ?: member.name))
        append("<br>at ").append(member.address)
    }

    override fun isLeaf() = true

    // Overloads share a name.
    override fun equals(other: Any?) = this === other
    override fun hashCode() = System.identityHashCode(this)
}

// The Symbol Tree's own icons, but for the ABI's objects: a table for a vtable, an info sign for the rest.
private val MEMBER_ICONS: Map<MemberKind, Icon> = mapOf(
    MemberKind.VTABLE to GIcon("icon.table"),
    MemberKind.ABI to GIcon("icon.information"),
    MemberKind.FUNCTION to GIcon("icon.plugin.symboltree.node.function"),
    MemberKind.THUNK to GIcon("icon.plugin.symboltree.node.function.thunk"),
    MemberKind.LABEL to GIcon("icon.plugin.symboltree.node.code"),
)

/**
 * Upstream's icon per kind of class: its green class icon with two colour channels swapped, so the
 * shape stays and the hue says the kind. A swept class with nothing more to say is the same in grey.
 */
private enum class Kind(val label: String, private val recolor: (Int, Int, Int) -> Triple<Int, Int, Int>) {
    NORMAL("class", { r, g, b -> Triple(r, g, b) }),
    ABSTRACT("abstract class", { r, g, b -> Triple(g, r, b) }),
    VIRTUAL("virtual base class", { r, g, b -> Triple(r, b, g) }),
    VIRTUAL_ABSTRACT("virtual abstract base class", { r, g, _ -> Triple(g, r, g) }),
    NESTED("nested class", { _, g, b -> Triple(g, g, b) }),
    SWEPT("class without stabs", ::greyscale),
    ;

    // Lazy: painting a themed icon needs the theme up, which a headless test that never draws skips.
    val icon: Icon by lazy { if (this == NORMAL) CLASS_ICON else CLASS_ICON.recolored(recolor) }
}

/** Rec. 601 luma, as a grey. */
private fun greyscale(r: Int, g: Int, b: Int) = ((299 * r + 587 * g + 114 * b) / 1000).let { Triple(it, it, it) }

/** [this] icon with [recolor] applied to every pixel's colour channels, alpha kept. */
private fun Icon.recolored(recolor: (Int, Int, Int) -> Triple<Int, Int, Int>): Icon {
    val w = iconWidth.coerceAtLeast(1)
    val h = iconHeight.coerceAtLeast(1)
    val image = BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB)
    image.createGraphics().also { paintIcon(null, it, 0, 0) }.dispose()
    for (y in 0 until h) {
        for (x in 0 until w) {
            val argb = image.getRGB(x, y)
            val (r, g, b) = recolor(argb shr 16 and 0xff, argb shr 8 and 0xff, argb and 0xff)
            image.setRGB(x, y, (argb and 0xff000000.toInt()) or (r shl 16) or (g shl 8) or b)
        }
    }
    return ImageIcon(image)
}

private fun escape(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

/** Namespaces before classes, then by name, as upstream sorts them. */
private val NODE_ORDER = compareBy<GTreeNode>({ it is ClassNode }, { it.name.lowercase() }, { it.name })
