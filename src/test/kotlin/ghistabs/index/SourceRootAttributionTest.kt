package ghistabs.index

import ghistabs.harvest.*
import ghistabs.parse.AggrKind
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.SourceFile
import ghistabs.parse.TypeDecl
import ghistabs.test.harvestOf
import ghistabs.test.must
import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/**
 * What a source root does to attribution: it moves a declaration to the file that declares it, and
 * only ever on a unique answer. The declarers function stands in for the real files here — reading
 * them is [ghistabs.scan.DeclaratorIndex]'s job and is tested there.
 */
class SourceRootAttributionTest {
    private val cu = SourceFile.CUSource("main.cpp")
    private val wrong = sourceFileOf("bits/basic_string.h")
    private val right = sourceFileOf("bits/stl_uninitialized.h")
    private var nextId = 1

    /** A typedef, the shape gcc keeps the line of and loses the file of (§38). */
    private fun typedef(name: String, line: Int, declaredIn: GhidraSourceFile) = Type(
        cu = cu,
        id = GlobalTypeId(cu, nextId++),
        name = name,
        body = TypeDecl.Ref(GlobalTypeId(cu, 0)),
        line = line,
        sourceFile = declaredIn,
    )

    private fun tag(name: String, line: Int, declaredIn: GhidraSourceFile) = Type(
        cu = cu,
        id = GlobalTypeId(cu, nextId++),
        name = name,
        body = TypeDecl.Struct(AggrKind.STRUCT, 4L, emptyList(), emptyList(), emptyList(), null),
        line = line,
        sourceFile = declaredIn,
    )

    /** [EffectiveSource] over [types], with [declarers] as the source root's answer. */
    private fun attribution(
        vararg types: Type,
        declarers: (Type.Decl) -> GhidraSourceFile? = { null },
    ): EffectiveSource {
        val harvest = harvestOf(*types)
        val graph = TypeGraph(harvest)
        val sources = SourceIndex(harvest, foldSources = false)
        return EffectiveSource(harvest, graph, sources, SourceHints(harvest, graph, sources), declarers = declarers)
    }

    @Test
    fun `a unique declarer takes the declaration off the file gcc recorded`() {
        val isPod = typedef("_Is_POD", 111, wrong)
        val sources = attribution(isPod) { (line, name) -> right.takeIf { name == "_Is_POD" && line == 111 } }

        sources.effectiveSourceFor(isPod) mustBe right
    }

    @Test
    fun `no answer and no root leave the declaration where it was`() {
        val isPod = typedef("_Is_POD", 111, wrong)
        attribution(isPod).effectiveSourceFor(isPod) mustBe wrong
        attribution(isPod) { null }.effectiveSourceFor(isPod) mustBe wrong
    }

    /**
     * §43's conflict rule exists because at most one claimant of a `(name, line)` can be right and
     * nothing said which. With a root, something does — so the pair stops being disputed and is
     * placed, rather than being displaced from every file that claimed it.
     */
    @Test
    fun `a declaration the root settles is no longer conflicted`() {
        val here = typedef("_Trivial", 426, wrong)
        val there = typedef("_Trivial", 426, right)
        attribution(here, there).conflictedTypedefDecls.must("two files, one line: disputed") {
            contains(Type.Decl(426, "_Trivial"))
        }

        val settled = attribution(here, there) { (line, name) -> right.takeIf { name == "_Trivial" && line == 426 } }
        settled.conflictedTypedefDecls mustBe emptySet<Type.Decl>()
        listOf(here, there).map(settled::effectiveSourceFor) mustBe listOf(right, right)
    }

    /** The guard the root itself is judged by must see attribution *without* it, or it decides its
     *  own input — a cycle in the reasoning and a self-forcing lazy in the code. */
    @Test
    fun `the base attribution keeps the recorded file whatever the root says`() {
        val isPod = typedef("_Is_POD", 111, wrong)
        val sources = attribution(isPod) { right }

        sources.baseTypesBySource[wrong] mustBe listOf(isPod)
        sources.typesBySource[right] mustBe listOf(isPod)
    }
}
