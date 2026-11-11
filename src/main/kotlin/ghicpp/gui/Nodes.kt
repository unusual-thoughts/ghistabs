package ghicpp.gui

import docking.widgets.tree.GTreeLazyNode
import docking.widgets.tree.GTreeNode
import docking.widgets.tree.support.GTreeRenderer
import generic.theme.GColor
import generic.theme.GIcon
import ghicpp.Access
import ghicpp.MemberAttrs
import ghicpp.VirtKind
import ghicpp.gui.Hues.*
import ghicpp.hierarchy.ClassHierarchy
import ghicpp.hierarchy.ClassHierarchy.*
import ghidra.program.model.symbol.SourceType
import java.awt.*
import java.awt.image.BufferedImage
import java.util.concurrent.ConcurrentHashMap
import javax.swing.Icon
import javax.swing.ImageIcon
import javax.swing.JTree

internal val CLASS_ICON: Icon = GIcon("icon.plugin.symboltree.node.class")

// Green: bases the binary states (stabs, RTTI) or set by hand. Grey: guessed by analysis, or none known.
private val SOLID_BASES = setOf(SourceType.IMPORTED, SourceType.USER_DEFINED)

private val NAMESPACE_ICON: Icon = GIcon("icon.plugin.symboltree.node.namespace")
private val ROOT_ICON: Icon = GIcon("icon.plugin.symboltree.node.category.classes.closed")

/**
 * The program's classes, filed by namespace, with their members unless [showMembers] is off. [inverted],
 * files only the basal classes, each expanding into the classes derived from it: a class with several
 * bases shows under each, and a virtual derivation is marked on the derived class.
 */
class ClassTreeRoot(
    private val programName: String,
    private val hierarchy: ClassHierarchy,
    val showMembers: Boolean = true,
    val inverted: Boolean = false,
    val showEmpty: Boolean = false,
) : GTreeNode() {
    init {
        val filed = (if (inverted) hierarchy.classes.filter(hierarchy::isBasal) else hierarchy.classes)
            .filter { showEmpty || !hierarchy.isEmpty(it) }
        val classNodes = filed.associate {
            it.path to ClassNode(hierarchy, it, inverted).also { n -> n.showMembers = showMembers }
        }
        val folders = mutableMapOf<List<String>, NamespaceNode>()
        val children = mutableMapOf<List<String>, MutableList<GTreeNode>>()

        // A namespace that is a class files what it holds as the class's nested classes.
        fun ensure(path: List<String>) {
            if (path.isEmpty() || path in classNodes || path in folders) return
            folders[path] = NamespaceNode(path)
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
    override fun getIcon(expanded: Boolean) = ROOT_ICON
    override fun getToolTip(): String? = null
    override fun isLeaf() = false

    /**
     * The node for the first of [addresses] the tree has: the member at it, else the class whose vtable
     * or typeinfo is there. Null when none is a class's.
     */
    fun nodeAt(addresses: List<String>): GTreeNode? = addresses.firstNotNullOfOrNull { a ->
        hierarchy.classes.firstNotNullOfOrNull { c ->
            c.members.firstOrNull { it.address == a }?.let { m ->
                nodeOf(c)?.children?.firstOrNull { it is MemberNode && it.member == m }
            }
        } ?: hierarchy.classes.firstOrNull { it.address == a }?.let(::nodeOf)
    }

    /**
     * The node of [cls] that lists its members: the one filed under its namespace, by name. Inverted,
     * that's under a basal class, so down from it through each class's first base it has a class for.
     */
    fun nodeOf(cls: ClassView): ClassNode? {
        val chain = generateSequence(cls) { c -> c.bases.firstNotNullOfOrNull { hierarchy[it] }.takeIf { inverted } }
            .toList().asReversed()
        var node: GTreeNode = this
        for (name in chain.first().path) {
            node = node.children.firstOrNull { n ->
                n.name == name && (n is NamespaceNode || (n is ClassNode && n.edge == null))
            } ?: return null
        }
        for (next in chain.drop(1)) {
            node = node.children.firstOrNull { it is ClassNode && it.info?.id == next.id } ?: return null
        }
        return node as? ClassNode
    }
}

/** A namespace that is not itself a class, at [path] (outermost first). */
class NamespaceNode(val path: List<String>) : GTreeNode() {
    override fun getName() = path.last()
    override fun getIcon(expanded: Boolean) = NAMESPACE_ICON
    override fun getToolTip(): String? = null
    override fun isLeaf() = false
}

/**
 * A class: [info] filed under its namespace, or reached by an [edge] from the class above it. Normally
 * that's a base, spelled the way the base clause does (`virtual protected Foo`), and a base the program
 * has no class for is a leaf. [inverted], it's a class derived from the one above, the clause's
 * virtuality and access after its name (`Left (virtual)`).
 */
class ClassNode private constructor(
    private val hierarchy: ClassHierarchy,
    val info: ClassView?,
    val edge: BaseRef?,
    private val inverted: Boolean,
) : GTreeLazyNode() {
    constructor(hierarchy: ClassHierarchy, info: ClassView, inverted: Boolean = false) :
        this(hierarchy, info, null, inverted)

    /** Classes declared inside this one; only a class filed under its namespace has them. */
    internal val nested = mutableListOf<GTreeNode>()

    private fun linked(): List<ClassNode> = if (inverted) {
        info?.let(hierarchy::derivedOf).orEmpty().map {
            ClassNode(hierarchy, it.cls, it.clause, true).also { n -> n.showMembers = showMembers }
        }
    } else {
        info?.bases.orEmpty().map { ClassNode(hierarchy, hierarchy[it], it, false) }
    }

    /** Set off by a root built without members. */
    internal var showMembers = true

    // Normally only the class filed under its namespace lists its members: under a base, they'd repeat.
    // Inverted, only the basal classes are filed, so every class lists them.
    private fun membersOf() = info?.members?.takeIf { (edge == null || inverted) && showMembers }.orEmpty()

    override fun generateChildren(): List<GTreeNode> = linked() + membersOf().map(::MemberNode) + nested

    private val qualifiers get() = edge?.let { e ->
        listOfNotNull("virtual".takeIf { e.isVirtual }, e.access?.takeIf { it != Access.PUBLIC }?.name?.lowercase())
    }.orEmpty()

    override fun getName(): String = when {
        edge == null -> info!!.name
        inverted -> info!!.qualifiedName + qualifiers.takeIf { it.isNotEmpty() }?.joinToString(" ", " (", ")").orEmpty()
        else -> (qualifiers + edge.name).joinToString(" ")
    }

    /** Set on a class filed under the class it's declared in. */
    internal var isNested = false

    // UNSOURCED only for a class the program has: a base with no class at all stays a plain class.
    private val kind get() = when {
        isNested -> Kind.NESTED
        edge?.isVirtual == true -> if (info?.isAbstract == true) Kind.VIRTUAL_ABSTRACT else Kind.VIRTUAL
        info?.isAbstract == true -> Kind.ABSTRACT
        info?.origin == Origin.LIBRARY -> Kind.LIBRARY
        info != null && info.origin.baseSource !in SOLID_BASES -> Kind.UNSOURCED
        else -> Kind.NORMAL
    }

    override fun getIcon(expanded: Boolean): Icon = kind.icon

    override fun getToolTip(): String = buildString {
        append("<html>")
        append(escape(info?.qualifiedName ?: edge?.name.orEmpty()))
        // The typedef shortening pass renamed its struct; the namespace keeps the long spelling.
        info?.structName?.takeIf { it != info.name }?.let { append("<br>shortened: ").append(escape(it)) }
        val origin = when (info?.origin) {
            Origin.EDITED -> "bases set by hand"
            Origin.STABS -> "from the stabs"
            Origin.MSVC_RTTI -> "from its MSVC RTTI"
            Origin.ITANIUM_RTTI -> "from its Itanium RTTI"
            Origin.SWEPT_RTTI -> "from its typeinfo"
            Origin.INFERRED -> "bases inferred from its constructors and vftables"
            Origin.SWEPT -> "from its vtable: bases unknown"
            Origin.NAMESPACE -> "from its namespace alone: bases unknown"
            Origin.LIBRARY -> "only imported: bases unknown"
            null -> "no class built for it: a plain struct, or only declared"
        }
        append("<br>").append(origin)
        if (kind !in setOf(Kind.NORMAL, Kind.UNSOURCED, Kind.LIBRARY)) {
            append("<br>").append(if (inverted) kind.derivedLabel else kind.label)
        }
        // Inverted, the clause is the derived class's: where that one holds the class above.
        edge?.offset?.let {
            append(if (inverted) "<br>holds it at 0x" else "<br>at offset 0x").append(it.toString(HEX))
        }
        info?.size?.let { append("<br>size 0x").append(it.toString(HEX)) }
        info?.vftable?.let { append("<br>vftable at ").append(it) }
        if (info?.vftable == null) info?.typeinfo?.let { append("<br>typeinfo at ").append(it) }
    }

    override fun isLeaf() =
        (if (inverted) info?.let(hierarchy::derivedOf).isNullOrEmpty() else info?.bases.isNullOrEmpty()) &&
            membersOf().isEmpty() && nested.isEmpty()

    // Two bases of one class can share a name (a direct and an indirect `Base`); never merge them. But
    // a node is its filtered clone, which the tree finds again by equals to keep it selected once the
    // filter is cleared.
    private val identity = Any()
    override fun equals(other: Any?) = other is ClassNode && other.identity === identity
    override fun hashCode() = identity.hashCode()
}

/**
 * A function or label of the class above it. Its icon's colour, and its text's ([color]), say its access
 * and virtuality, or that it is imported, and a `c`/`v` badge on the icon its cv-qualifiers ([memberIcon]).
 */
class MemberNode(val member: Member) : GTreeNode() {
    override fun getName() = member.label
    override fun getIcon(expanded: Boolean): Icon = memberIcon(member.kind, member.attrs, member.library != null)
    override fun getToolTip(): String = buildString {
        append("<html>").append(escape(member.signature ?: member.name))
        member.attrs?.describe()?.takeIf { it.isNotEmpty() }?.let { append("<br>").append(it) }
        member.library?.let { append("<br>imported from ").append(escape(it)) }
        member.aliases.forEach { append("<br>also ").append(escape(it)) }
        append("<br>at ").append(member.address)
    }

    /** Its icon's colours ([memberIcon]) for its text: none for the program's own vtable or other ABI object. */
    val color: Color? get() {
        val attrs = member.attrs
        val hue = when {
            member.library != null -> IMPORTED_COLOR
            attrs == null -> return null
            else -> attrs.virt?.let(VIRT_COLORS::get) ?: UNKNOWN_COLOR
        }
        return when (attrs?.access) {
            Access.PRIVATE -> hue.mix(Color.BLACK, PRIVATE_SHADE)
            Access.PROTECTED -> hue.mix(Color.WHITE, PROTECTED_TINT)
            else -> hue
        }
    }

    override fun isLeaf() = true

    // Overloads share a name: equal only to its own filtered clone, as a [ClassNode].
    private val identity = Any()
    override fun equals(other: Any?) = other is MemberNode && other.identity === identity
    override fun hashCode() = identity.hashCode()
}

/** Where going to [node] goes. */
internal val GTreeNode.address: String? get() = when (this) {
    is MemberNode -> member.address
    is ClassNode -> info?.address
    else -> null
}

/** A namespace node's path, or the root's (empty); null for a class. */
internal val GTreeNode.namespacePath: List<String>? get() = when (this) {
    is ClassTreeRoot -> emptyList()
    is NamespaceNode -> path
    else -> null
}

enum class Hues(val hue: Float) {
    RED(0f),
    ORANGE(1f / 12),
    YELLOW(1f / 6),
    GREEN(1f / 3),
    CYAN(1f / 2),
    TEAL(7f / 12),
    BLUE(2f / 3),
    MAGENTA(5f / 6),
}

// The Symbol Tree's own icons, but for the ABI's objects: a table for a vtable, an info sign for the rest.
// Each with the hue, in degrees, it is drawn in, which a tint turns from.
private val MEMBER_ICONS: Map<MemberKind, Pair<Icon, Float>> = mapOf(
    MemberKind.VTABLE to (GIcon("icon.table") to TEAL.hue),
    MemberKind.ABI to (GIcon("icon.information") to TEAL.hue),
    MemberKind.FUNCTION to (GIcon("icon.plugin.symboltree.node.function") to MAGENTA.hue),
    MemberKind.THUNK to (GIcon("icon.plugin.symboltree.node.function.thunk") to MAGENTA.hue),
    MemberKind.LABEL to (GIcon("icon.plugin.symboltree.node.code") to GREEN.hue),
)

/**
 * Upstream's icon per kind of class: its green class icon turned to the kind's hue, so the shape and
 * shading stay and the hue says the kind. A class whose bases nothing records, with nothing more to
 * say, is the same in grey.
 */
private enum class Kind(
    val label: String,
    /** The same, said of a class derived from the one above it in the inverted tree. */
    val derivedLabel: String,
    /** The hue, in degrees, the class icon's green turns to; grey when null. */
    private val hue: Float?,
) {
    NORMAL("class", "class", GREEN.hue),
    ABSTRACT("abstract class", "abstract class", RED.hue),
    VIRTUAL("virtual base class", "derives virtually", BLUE.hue),
    VIRTUAL_ABSTRACT("virtual abstract base class", "abstract, derives virtually", MAGENTA.hue),
    NESTED("nested class", "nested class", YELLOW.hue),
    UNSOURCED("class, bases from analysis or unknown", "class, bases from analysis or unknown", null),

    // As its imported members.
    LIBRARY("imported class", "imported class", ORANGE.hue),
    ;

    // Lazy: painting a themed icon needs the theme up, which a headless test that never draws skips.
    val icon: Icon by lazy { if (this == NORMAL) CLASS_ICON else CLASS_ICON.hueShifted(GREEN.hue, hue) }
}

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

// Each [MemberKind]'s icon per set of attributes, made once when first drawn.
private val memberIcons = ConcurrentHashMap<Triple<MemberKind, MemberAttrs?, Boolean>, Icon>()

/**
 * [kind]'s icon in its [attrs]' colours, as the class icons say their kind: the hue of its virtuality
 * ([VIRT_COLORS]; the function icon's own magenta for a plain member, grey when unknown), darker when
 * private and paler when protected, with a `c`/`v` badge for its cv-qualifiers. An [imported] member is
 * [IMPORTED_COLOR] whatever its virtuality. The program's own vtable or other ABI object, with no
 * attributes, keeps its icon.
 */
private fun memberIcon(kind: MemberKind, attrs: MemberAttrs?, imported: Boolean): Icon =
    memberIcons.getOrPut(Triple(kind, attrs?.copy(), imported)) {
        val (base, from) = MEMBER_ICONS.getValue(kind)
        val icon = base.centered()
        if (attrs == null && !imported) return@getOrPut icon
        val hue = if (imported) IMPORTED_COLOR else attrs?.virt?.let(VIRT_COLORS::get)
        val to = hue?.let { Color.RGBtoHSB(it.red, it.green, it.blue, null)[0] }
        val tinted = icon.hueShifted(from, to, attrs?.access)
        val badge = "c".takeIf { attrs?.isConst == true }.orEmpty() + "v".takeIf { attrs?.isVolatile == true }.orEmpty()
        if (badge.isEmpty()) tinted else tinted.badged(badge)
    }

/**
 * [this] icon, drawn in hue [from], turned to hue [to] (degrees), greyed when [to] is null: every pixel's
 * hue rotates by the same angle, so shading in other hues rotates with it, and its saturation and
 * brightness stay. Then darkened for [Access.PRIVATE] or paled for [Access.PROTECTED]. Grey pixels stay grey.
 */
private fun Icon.hueShifted(from: Float, to: Float?, access: Access? = null): Icon {
    val shift = ((to ?: from) - from)
    return recolored { r, g, b ->
        val (hue, sat, bright) = Color.RGBtoHSB(r, g, b, null)
        var s = if (to == null) 0f else sat
        var v = bright
        when (access) {
            Access.PRIVATE -> v *= (1 - PRIVATE_SHADE).toFloat()

            Access.PROTECTED -> {
                s *= (1 - PROTECTED_TINT).toFloat()
                v += (1 - v) * PROTECTED_TINT.toFloat()
            }

            else -> {}
        }
        // HSBtoRGB takes the hue's fractional part: a turn past red wraps.
        val rgb = Color.HSBtoRGB(hue + shift, s, v)
        Triple(rgb shr 16 and 0xff, rgb shr 8 and 0xff, rgb and 0xff)
    }
}

/**
 * [this] icon in the middle of a [size]-pixel square: the label icon is 8x8, and the renderer leaves a
 * small icon flush left in the column the others fill, so its dot sat off their centre line.
 */
private fun Icon.centered(size: Int = MEMBER_ICON_SIZE): Icon {
    if (iconWidth >= size && iconHeight >= size) return this
    val image = BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB)
    val g = image.createGraphics()
    try {
        paintIcon(null, g, (size - iconWidth) / 2, (size - iconHeight) / 2)
    } finally {
        g.dispose()
    }
    return ImageIcon(image)
}

private const val MEMBER_ICON_SIZE = 16

/** [this] icon with [text] in small bold type over its bottom-right corner, haloed to read on any icon. */
private fun Icon.badged(text: String): Icon {
    val w = iconWidth.coerceAtLeast(1)
    val h = iconHeight.coerceAtLeast(1)
    val image = BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB)
    val g = image.createGraphics()
    try {
        paintIcon(null, g, 0, 0)
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
        g.font = Font(Font.SANS_SERIF, Font.BOLD, BADGE_POINTS)
        val metrics = g.fontMetrics
        val x = w - metrics.stringWidth(text)
        val y = h - metrics.descent + 1
        val outline = g.font.createGlyphVector(g.fontRenderContext, text).getOutline(x.toFloat(), y.toFloat())
        g.color = Color.WHITE
        g.stroke = BasicStroke(2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
        g.draw(outline)
        g.color = Color.BLACK
        g.fill(outline)
    } finally {
        g.dispose()
    }
    return ImageIcon(image)
}

private const val BADGE_POINTS = 9

// A plain member is the function icon's own magenta; one whose virtuality no source records is grey.
private val VIRT_COLORS: Map<VirtKind, Color> = mapOf(
    VirtKind.NORMAL to GColor("color.palette.magenta"),
    VirtKind.STATIC to GColor("color.palette.green"),
    VirtKind.VIRTUAL to GColor("color.palette.blue"),
)
private val UNKNOWN_COLOR: Color = GColor("color.palette.gray")

// What the program imports from a library, as the Symbol Tree's own external functions are drawn apart.
private val IMPORTED_COLOR: Color = GColor("color.palette.orange")
private const val PRIVATE_SHADE = 0.4
private const val PROTECTED_TINT = 0.45

/** [this] colour moved [amount] of the way to [other]. */
private fun Color.mix(other: Color, amount: Double): Color {
    fun channel(a: Int, b: Int) = (a + (b - a) * amount).toInt()
    return Color(channel(red, other.red), channel(green, other.green), channel(blue, other.blue))
}

/** `private virtual const`: what is known of it, as C++ would spell it; unknown parts are left out. */
private fun MemberAttrs.describe() = listOfNotNull(
    access?.name?.lowercase(),
    virt?.takeIf { it != VirtKind.NORMAL }?.name?.lowercase(),
    "const".takeIf { isConst },
    "volatile".takeIf { isVolatile },
).joinToString(" ")

/** The tree's renderer, with each [MemberNode] in its [MemberNode.color] while unselected. */
internal class ClassTreeRenderer : GTreeRenderer() {
    override fun getTreeCellRendererComponent(
        tree: JTree,
        value: Any?,
        selected: Boolean,
        expanded: Boolean,
        leaf: Boolean,
        row: Int,
        hasFocus: Boolean,
    ): Component {
        super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus)
        if (!selected) (value as? MemberNode)?.color?.let { foreground = it }
        return this
    }
}

private fun escape(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

/** Namespaces before classes, then by name, as upstream sorts them. */
private val NODE_ORDER = compareBy<GTreeNode>({ it is ClassNode }, { it.name.lowercase() }, { it.name })

internal const val HEX = 16
