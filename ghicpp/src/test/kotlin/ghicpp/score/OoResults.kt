package ghicpp.score

import ghicpp.MemberAttrs
import ghicpp.VirtKind
import ghicpp.hierarchy.ClassHierarchy
import ghicpp.hierarchy.ClassHierarchy.BaseRef
import ghicpp.hierarchy.ClassHierarchy.ClassView
import ghicpp.hierarchy.ClassHierarchy.Member
import ghicpp.hierarchy.ClassHierarchy.MemberKind
import ghicpp.hierarchy.ClassHierarchy.Origin

/**
 * OOAnalyzer's Prolog results (`ooprolog --results`), read back as the [Snapshot] a recovery leaves, for the
 * [Scorer] to score as it does ours. Each `finalClass` is a class named by its id, `cls_<id>`, or by the RTTI
 * name its vftable carries; its methods are functions, a constructor named after the class, a destructor
 * `~` it, as the scorer tells structors; `finalInheritance` gives its bases, `finalMember` its own fields,
 * laid out with its bases' and embedded objects' at their offsets as a struct would be. A class whose vftable
 * holds one of [purecalls] is abstract. An RTTI name is the class [demangled] says it spells.
 */
class OoResults(
    text: String,
    private val purecalls: Set<Long> = emptySet(),
    /** The class each RTTI type name (`.?AVShape@@`) spells, as the facts' `rTTITypeDescriptor` gave it. */
    private val demangled: Map<String, String> = emptyMap(),
) {
    val terms: List<Pair<String, List<Any>>> = text.lineSequence().map { it.trim() }
        .filter { it.isNotEmpty() && !it.startsWith("%") }
        .map { PrologTerm(it).fact() }.toList()

    private fun all(name: String) = terms.filter { it.first == name }.map { it.second }

    fun snapshot(fixture: String): Snapshot {
        val vftNames = all("finalVFTable").associate {
            (it[0] as Long) to
                (it[4] as? String)?.takeIf { n -> n.isNotEmpty() }?.let { n -> demangled[n] ?: n }
        }
        val entries = all("finalVFTableEntry").groupBy({ it[0] as Long }, { it[2] as Long })
        val props = all("finalMethodProperty").groupBy({ it[0] as Long }, { it[1] as String })
        val classes = all("finalClass").map { c -> OoClass(c) }
        val names = classes.associate { c -> c.id to (c.vftable?.let(vftNames::get) ?: "cls_%x".format(c.id)) }
        val inheritance = all("finalInheritance")
        val members = all("finalMember").groupBy({ it[0] as Long }, {
            (it[1] as Long) to
                (it[2] as List<*>).maxOf { s -> s as Long }
        })
        val embedded = all("finalEmbeddedObject").groupBy({ it[0] as Long }, { (it[1] as Long) to (it[2] as Long) })

        fun bases(id: Long) = inheritance.filter { it[0] == id }

        fun fields(id: Long, at: Long, into: MutableMap<Long, Int>, seen: Set<Long>) {
            if (id in seen) return
            members[id].orEmpty().forEach { (off, size) -> into.putIfAbsent(at + off, size.toInt()) }
            bases(id).filter { it[4] != "true" && it[4] != true }.forEach {
                fields(
                    it[1] as Long,
                    at + it[2] as Long,
                    into,
                    seen + id,
                )
            }
            embedded[id].orEmpty().forEach { (off, inner) -> fields(inner, at + off, into, seen + id) }
        }

        val views = classes.map { c ->
            val name = names.getValue(c.id)
            val path = name.split("::")
            val functions = c.methods.map { m ->
                val p = props[m].orEmpty()
                val fname = when {
                    "constructor" in p -> path.last()
                    "realDestructor" in p || "deletingDestructor" in p -> "~" + path.last()
                    else -> "FUN_%08x".format(m)
                }
                val virt = if ("virtual" in p) VirtKind.VIRTUAL else null
                Member(fname, "%08x".format(m), MemberKind.FUNCTION, attrs = virt?.let { MemberAttrs(virt = it) })
            }
            val vtable = c.vftable?.let { listOf(Member("vftable", "%08x".format(it), MemberKind.VTABLE)) }.orEmpty()
            ClassView(
                id = c.id,
                path = path,
                origin = if (c.vftable?.let(vftNames::get) != null) Origin.MSVC_RTTI else Origin.INFERRED,
                vftable = c.vftable?.let { "%08x".format(it) },
                vftableStructId = null,
                typeinfo = null,
                structId = null,
                structName = null,
                isAbstract = c.vftable?.let { entries[it].orEmpty().any(purecalls::contains) } == true,
                members = vtable + functions,
                bases = bases(c.id).map { b ->
                    val virtual = b[4] == "true" || b[4] == true
                    val base = b[1] as Long
                    BaseRef(
                        names[base] ?: "cls_%x".format(base),
                        base,
                        virtual,
                        null,
                        (b[2] as Long).takeIf {
                            !virtual
                        },
                    )
                },
                size = c.size,
            )
        }
        val fieldMap = classes.associate { c ->
            c.id to
                sortedMapOf<Long, Int>().also { fields(c.id, 0, it, emptySet()) }
        }
            .filterValues { it.isNotEmpty() }
        return Snapshot(fixture, ClassHierarchy(views), fieldMap)
    }

    /** `finalClass(ClassID, VFTableOrNull, CertainSize, LikelySize, RealDestructorOrNull, MethodList)`. */
    private class OoClass(args: List<Any>) {
        val id = args[0] as Long
        val vftable = (args[1] as Long).takeIf { it != 0L }
        val size = (args[3] as Long).takeIf { it > 0 }
        val methods = (args[5] as List<*>).map { it as Long }
    }
}

/**
 * Just enough Prolog to read a results line back: `name(arg, …).` whose arguments are numbers (`0x` hex or
 * decimal, possibly negative), atoms (bare or quoted) and lists of those. Atoms come back as strings.
 */
class PrologTerm(private val s: String) {
    private var i = 0

    fun fact(): Pair<String, List<Any>> {
        val name = atom()
        val args = if (peek() == '(') list('(', ')') else emptyList()
        return name to args
    }

    private fun peek(): Char? {
        while (i < s.length && s[i].isWhitespace()) i++
        return s.getOrNull(i)
    }

    private fun value(): Any = when (val c = peek()) {
        '[' -> list('[', ']')

        '\'' -> quoted()

        '-' -> {
            i++
            -(value() as Long)
        }

        null -> error("end of term in $s")

        else -> if (c.isDigit()) number() else atom().let { a -> if (peek() == '(') a + list('(', ')') else a }
    }

    private fun list(open: Char, close: Char): List<Any> {
        check(peek() == open)
        i++
        val out = mutableListOf<Any>()
        if (peek() == close) {
            i++
            return out
        }
        while (true) {
            out += value()
            when (peek()) {
                ',' -> i++

                close -> {
                    i++
                    return out
                }

                else -> error("unexpected '${s.getOrNull(i)}' at $i in $s")
            }
        }
    }

    private fun number(): Long {
        val start = i
        while (i < s.length && (s[i].isLetterOrDigit())) i++
        val text = s.substring(start, i)
        return if (text.startsWith("0x")) text.substring(2).toLong(16) else text.toLong()
    }

    private fun atom(): String {
        peek()
        if (s.getOrNull(i) == '\'') return quoted()
        val start = i
        while (i < s.length && (s[i].isLetterOrDigit() || s[i] == '_')) i++
        return s.substring(start, i)
    }

    private fun quoted(): String {
        i++
        val out = StringBuilder()
        while (s[i] != '\'' || s.getOrNull(i + 1) == '\'') {
            if (s[i] == '\\') {
                i++
            } else if (s[i] == '\'') {
                i++
            }
            out.append(s[i++])
        }
        i++
        return out.toString()
    }
}
