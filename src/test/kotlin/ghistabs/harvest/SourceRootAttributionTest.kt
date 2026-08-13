package ghistabs.harvest

import ghistabs.parse.AggrKind
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.SourceFile
import ghistabs.parse.TypeDecl
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/**
 * What a source root does to attribution: it moves a declaration to the file that declares it, and
 * only ever on a unique answer. The declarers hook stands in for the real files here — reading them
 * is [ghistabs.scan.DeclaratorIndex]'s job and is tested there.
 */
class SourceRootAttributionTest {
    private val cu = SourceFile.CUSource("unpackfile.cpp")
    private val wrong = sourceFileOf("bits/basic_string.h")
    private val right = sourceFileOf("bits/stl_uninitialized.h")
    private var nextId = 1

    /** A typedef, the shape gcc keeps the line of and loses the file of (§38). */
    private fun typedef(name: String, line: Int, declaredIn: GhidraSourceFile) = Type(
        cu = cu,
        id = GlobalTypeId(cu, nextId++),
        name = name,
        body = TypeDecl.Ref(GlobalTypeId(cu, 0)),
        declLine = line,
        declSourceFile = declaredIn,
    )

    private fun tag(name: String, line: Int, declaredIn: GhidraSourceFile) = Type(
        cu = cu,
        id = GlobalTypeId(cu, nextId++),
        name = name,
        body = TypeDecl.Struct(AggrKind.CLASS, 4L, emptyList(), emptyList(), emptyList(), null),
        declLine = line,
        declSourceFile = declaredIn,
    )

    private fun indexOf(vararg types: Type) = HarvestIndex(Harvest.of(types.associateBy { it.id }), foldSources = false)

    @Test
    fun `a unique declarer takes the declaration off the file gcc recorded`() {
        val isPod = typedef("_Is_POD", 111, wrong)
        val index = indexOf(isPod)
        index.declarers = { name, line -> right.takeIf { name == "_Is_POD" && line == 111 } }

        assertEquals(right, index.effectiveSourceFor(isPod))
    }

    @Test
    fun `no answer and no root leave the declaration where it was`() {
        val isPod = typedef("_Is_POD", 111, wrong)
        assertEquals(wrong, indexOf(isPod).effectiveSourceFor(isPod))

        val asked = indexOf(isPod).also { it.declarers = { _, _ -> null } }
        assertEquals(wrong, asked.effectiveSourceFor(isPod))
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
        val disputed = indexOf(here, there)
        assertTrue(("_Trivial" to 426) in disputed.conflictedTypedefDecls, "two files, one line: disputed")

        val settled = indexOf(here, there)
        settled.declarers = { name, line -> right.takeIf { name == "_Trivial" && line == 426 } }
        assertEquals(emptySet<Pair<String, Int>>(), settled.conflictedTypedefDecls)
        assertEquals(listOf(right, right), listOf(here, there).map(settled::effectiveSourceFor))
    }

    /** The guard the root itself is judged by must see attribution *without* it, or it decides its
     *  own input — a cycle in the reasoning and a self-forcing lazy in the code. */
    @Test
    fun `the base attribution keeps the recorded file whatever the root says`() {
        val isPod = typedef("_Is_POD", 111, wrong)
        val index = indexOf(isPod)
        index.declarers = { _, _ -> right }

        assertEquals(listOf(isPod), index.baseTypesBySource[wrong])
        assertEquals(listOf(isPod), index.typesBySource[right])
    }

    /** Installed late, the root would be silently ignored: the per-source views memoise. */
    @Test
    fun `installing a root after attribution has been read is refused`() {
        val index = indexOf(tag("_Vector_alloc_base", 79, wrong))
        index.typesBySource

        assertThrows(IllegalStateException::class.java) { index.declarers = { _, _ -> right } }
    }
}
