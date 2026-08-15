package ghistabs.render

import ghistabs.harvest.GhidraSourceFile
import ghistabs.harvest.Type
import ghistabs.scan.Definition
import kotlin.math.abs

/**
 * §44's measurement, as something the build produces: what the real source says about the two
 * attributions the render makes — which function an inlined stretch was compiled from, and which
 * file declares a type.
 *
 * Graded only where a source root resolved a local file. A file the root did not map is not evidence
 * either way and is counted apart rather than scored as a miss: the naming miss rate and the *root's*
 * coverage are different numbers, and §45 turns on the difference.
 *
 * The inline half is not recomputed here — it is read off the questions the render itself put
 * ([Renderer.enclosings]), so what is graded is what the output says.
 */
class Scorecard(private val renderer: Renderer) {
    /** How the file a declaration is attributed to grades it. */
    enum class Verdict(val label: String) {
        LINE_EXACT("right line (±$SLACK)"),
        LINE_WRONG("right file, wrong line"),
        NAME_ABSENT("name absent from the file"),
        PAST_EOF("past EOF"),
    }

    /** One `(file, name, line)` declaration and the verdict its file's real text gives it. */
    data class Graded(
        val name: String,
        val source: GhidraSourceFile,
        val line: Int,
        val verdict: Verdict,
        val declaredAt: List<Int>,
    ) {
        override fun toString() = "$name ${source.filename}:$line — " + when (verdict) {
            Verdict.LINE_EXACT, Verdict.LINE_WRONG -> "source declares it at ${declaredAt.joinToString()}"
            Verdict.NAME_ABSENT -> "the source never names it"
            Verdict.PAST_EOF -> "the file ends first"
        }
    }

    /** A place the render asked the source to name a stretch, and what came back. */
    data class Stretch(val source: GhidraSourceFile, val line: Int, val definition: Definition?, val mapped: Boolean)

    private val index = renderer.index

    private val stretches by lazy {
        renderer.enclosings.map { (place, definition) ->
            Stretch(place.first, place.second, definition, renderer.localSources[place.first] != null)
        }
    }

    private val named by lazy { stretches.filter { it.definition != null } }
    private val unnamed by lazy { stretches.filter { it.definition == null && it.mapped } }
    private val unmapped by lazy { stretches.filter { !it.mapped } }

    /** One attribution's declarations: how many distinct ones it places, and the graded subset. */
    class Grades(val total: Int, val graded: List<Graded>) {
        operator fun get(verdict: Verdict) = graded.count { it.verdict == verdict }
    }

    /** Where the render places each declaration. */
    val declarations by lazy { gradeAll { index.effectiveSourceFor(it) } }

    /**
     * Where it placed them before the root had a say — §44's own table, so the two columns say what
     * re-attribution (§46) bought rather than only what the current attribution scores.
     */
    val base by lazy { gradeAll { baseById[it.id] } }

    private val baseById by lazy {
        index.baseTypesBySource.flatMap { (source, types) -> types.map { it.id to source } }.toMap()
    }

    private fun gradeAll(sourceOf: (Type) -> GhidraSourceFile?): Grades {
        val decls = index.allTypes
            .mapNotNull { type ->
                type.declLine?.let { line ->
                    type.name?.substringBefore('<')
                        ?.let { name -> sourceOf(type)?.let { Triple(it, name, line) } }
                }
            }
            .distinct()
        return Grades(decls.size, decls.mapNotNull { (source, name, line) -> grade(source, name, line) })
    }

    /**
     * The declarations the root moved (§46), with the file they were filed under before it had a say
     * — the one fact here the source is not asked for, attribution having already decided it.
     */
    val moved: List<Triple<String, GhidraSourceFile, GhidraSourceFile>> by lazy {
        index.allTypes
            .filter { it.name != null && it.declLine != null }
            .mapNotNull { type ->
                val from = baseById[type.id] ?: return@mapNotNull null
                index.effectiveSourceFor(type)
                    .takeIf { it != from }
                    ?.let { Triple("${type.name!!.substringBefore('<')} L${type.declLine}", from, it) }
            }
    }

    /** The moves as declarations rather than as instances: one `(name, line)` moved out of four CUs
     *  at once is one declaration re-filed, four times over. */
    private val movedDecls by lazy { moved.map { it.first }.distinct() }

    private fun grade(source: GhidraSourceFile, name: String, line: Int): Graded? {
        val declaredAt = renderer.declaredAt(source, name) ?: return null
        val length = renderer.lengthOf(source) ?: return null
        val verdict = when {
            line > length -> Verdict.PAST_EOF
            declaredAt.isEmpty() -> Verdict.NAME_ABSENT
            declaredAt.any { abs(it - line) <= SLACK } -> Verdict.LINE_EXACT
            else -> Verdict.LINE_WRONG
        }
        return Graded(name, source, line, verdict, declaredAt)
    }

    /**
     * The same facts as counters, so the run's diagnostics carry them alongside the dump and a
     * regression is greppable. Silent without a root: nothing was mapped, so nothing was graded, and
     * a row of zeroes would read as a score.
     */
    fun tally() {
        if (renderer.sources.none { renderer.localSources[it] != null }) return
        val gradedStretches = stretches.size - unmapped.size
        index.log("inlines-named", "${named.size} of $gradedStretches mapped", count = named.size.toLong())
        index.log("inlines-unnamed", count = unnamed.size.toLong())
        index.log("inlines-unmapped", "the stretch's own header has no local file", count = unmapped.size.toLong())
        Verdict.entries.forEach { v ->
            index.log(v.counter, "${v.label}, of ${declarations.graded.size} graded", count = declarations[v].toLong())
        }
        index.log("decl-ungraded", count = (declarations.total - declarations.graded.size).toLong())
        index.log("decl-reattributed", "${movedDecls.size} distinct", count = moved.size.toLong())

        unnamed.forEach { index.debug("inline-unnamed", "${it.source.filename}:${it.line}") }
        declarations.graded.filter { it.verdict != Verdict.LINE_EXACT }
            .forEach { index.debug("decl-misplaced", "$it") }
        moved.distinct().forEach { (decl, from, to) ->
            index.debug("decl-moved", "$decl: ${from.filename} → ${to.filename}")
        }
    }

    /**
     * The table, then the items behind it. The itemisation is the point: a bare percentage would not
     * have found `rebind` → stl_alloc.h:661 (§44), and it is what makes a regression readable as a
     * list of declarations rather than as a number that moved.
     */
    fun report(title: String) = buildString {
        val mapped = renderer.sources.count { renderer.localSources[it] != null }
        appendLine("attribution scorecard — $title")
        appendLine("$mapped of ${renderer.sources.size} sources resolved to a local file")

        appendLine("\ninlined stretches — ${stretches.size} distinct (file, line)")
        appendLine(row("named", named.size, stretches.size - unmapped.size))
        appendLine(row("unnamed", unnamed.size, stretches.size - unmapped.size))
        appendLine(row("file not mapped", unmapped.size, stretches.size))

        appendLine("\ndeclarations                    before root    after root")
        appendLine(
            pair("with ground truth", base.graded.size, base.total, declarations.graded.size, declarations.total),
        )
        Verdict.entries.forEach { v ->
            appendLine(pair(v.label, base[v], base.graded.size, declarations[v], declarations.graded.size))
        }

        // Against the *base* attribution, so it counts what the root changed rather than what it
        // disagrees with gcc about: a declaration the §15 hint had already moved is not moved again.
        appendLine("\nre-attributed by the root — ${movedDecls.size} distinct, ${moved.size} instances")

        section("unnamed inlines", unnamed.map { "${it.source.filename}:${it.line}" })
        Verdict.entries.filter { it != Verdict.LINE_EXACT }.forEach { v ->
            section(v.label, declarations.graded.filter { it.verdict == v }.map { "$it" })
        }
        section(
            "re-attributed",
            moved.distinct().map { (decl, from, to) -> "$decl: ${from.filename} → ${to.filename}" },
        )
    }

    private fun StringBuilder.section(title: String, items: List<String>) {
        appendLine("\n$title (${items.size})")
        items.sorted().forEach { appendLine("  $it") }
    }

    private fun row(label: String, n: Int, of: Int) = "  %-24s %5d %4s".format(label, n, percent(n, of))

    private fun pair(label: String, n: Int, of: Int, m: Int, ofM: Int) =
        "  %-24s %5d %4s   %5d %4s".format(label, n, percent(n, of), m, percent(m, ofM))

    private fun percent(n: Int, of: Int) = if (of > 0) "${100 * n / of}%" else ""
}

private val Scorecard.Verdict.counter get() = "decl-" + name.lowercase().replace('_', '-')

/** How far off the source's own line gcc's may be — it dates a declaration at its opening brace. */
private const val SLACK = 3
