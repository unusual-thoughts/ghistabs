package ghistabs.importer

import ghistabs.test.mustBe
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText

/**
 * Derivation over a real temp tree: which local directory a recorded one is, decided by shared
 * trailing segments first and by the recorded files being there second.
 */
class SourceRootTest {
    @TempDir
    lateinit var root: Path

    private fun tree(vararg files: String) = files.forEach { relative ->
        root.resolve(relative).also { it.parent.createDirectories() }.writeText("// $relative\n")
    }

    private fun derive(dir: String, vararg files: String) = SourceRoot(root).derive(mapOf(dir to files.toSet()))

    @Test
    fun `the directory holding the recorded files wins over same-named ones that do not`() {
        tree(
            "libstdc++-v3/include/bits/stl_vector.h",
            "libstdc++-v3/config/cpu/i486/bits/atomicity.h",
            "libstdc++-v3/config/os/mingw32/bits/ctype_base.h",
        )
        val derived = derive("/c:/mingw/include/c++/3.2.3/bits/", "stl_vector.h", "stl_alloc.h")

        derived.transforms mustBe
            listOf(DirectoryTransform("/c:/mingw/include/c++/3.2.3/bits/", "$root/libstdc++-v3/include/bits/"))
    }

    /** gcc keeps one `atomicity.h` per architecture. Nothing about the recorded path says which was
     *  compiled in, so the pair is reported and neither is registered. */
    @Test
    fun `equally good candidates are reported, not guessed between`() {
        tree(
            "config/cpu/i486/bits/atomicity.h",
            "config/cpu/arm/bits/atomicity.h",
        )
        val derived = derive("/c:/mingw/include/c++/3.2.3/mingw32/bits/", "atomicity.h")

        derived.transforms mustBe emptyList<DirectoryTransform>()
        derived.ambiguous.getValue("/c:/mingw/include/c++/3.2.3/mingw32/bits/") mustBe
            listOf("$root/config/cpu/arm/bits", "$root/config/cpu/i486/bits")
    }

    /** Two shared segments beat one, before the files are ever consulted — so a decoy holding a
     *  same-named file cannot outrank the directory that is actually in the right place. */
    @Test
    fun `deeper agreement on the path wins first`() {
        tree("proj/util/project/image.h", "vendor/project/image.h")
        val derived = derive("/E:/work/cc/util/project/", "image.h")

        derived.transforms.single().local mustBe "$root/proj/util/project/"
    }

    /** The installed `mingw32/bits/` against gcc's own tree: `config/os/mingw32/bits/` agrees on two
     *  segments and holds none of the files, which sit one tier down in every architecture's
     *  `config/cpu/<arch>/bits/`. Falling through is what turns "absent" into the ambiguity it is. */
    @Test
    fun `a deeper directory without the files falls through to the tier that has them`() {
        tree(
            "config/os/mingw32/bits/ctype_base.h",
            "config/cpu/i486/bits/atomicity.h",
            "config/cpu/arm/bits/atomicity.h",
        )
        val derived = derive("/c:/mingw/include/c++/3.2.3/mingw32/bits/", "atomicity.h")

        derived.transforms mustBe emptyList<DirectoryTransform>()
        derived.ambiguous.getValue("/c:/mingw/include/c++/3.2.3/mingw32/bits/") mustBe
            listOf("$root/config/cpu/arm/bits", "$root/config/cpu/i486/bits")
    }

    @Test
    fun `a directory whose files are absent is unmatched, not mapped`() {
        tree("include/bits/stl_vector.h")
        val derived = derive("/c:/mingw/include/c++/3.2.3/bits/", "unrelated.h")

        derived.transforms mustBe emptyList<DirectoryTransform>()
        derived.unmatched mustBe listOf("/c:/mingw/include/c++/3.2.3/bits/")
    }

    @Test
    fun `a directory the root knows nothing about is unmatched`() {
        tree("include/bits/stl_vector.h")
        val derived = derive("/E:/work/cc/devtools/imageutil/", "xdvimage.h")

        derived.unmatched mustBe listOf("/E:/work/cc/devtools/imageutil/")
    }
}
