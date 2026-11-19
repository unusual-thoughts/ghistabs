package ghistabs.build

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.createFile

class GhidraJavadocTest {
    @Test
    fun `a class page is its outer class's source, a package summary its directory`() {
        assertEquals("a/b/Foo.java", GhidraJavadoc.sourceOf("a/b/Foo.html"))
        assertEquals("a/b/Foo.java", GhidraJavadoc.sourceOf("a/b/Foo.Bar.Baz.html"))
        assertEquals("a/b/", GhidraJavadoc.sourceOf("a/b/package-summary.html"))
    }

    @Test
    fun `indexes, trees and uses document no source`() {
        for (page in listOf("index.html", "a/b/package-tree.html", "a/b/package-use.html", "a/b/class-use/Foo.html")) {
            assertNull(GhidraJavadoc.sourceOf(page), page)
        }
    }

    @Test
    fun `pages the official javadoc lacks map to their modules`(@TempDir api: Path) {
        for (page in listOf(
            "a/Foo.html",
            "a/Bar.html",
            "a/Bar.Inner.html",
            "a/package-summary.html",
            "a/class-use/Foo.html",
        )) {
            api.resolve(page).also { it.parent.createDirectories() }.createFile()
        }
        val modules = mapOf("a/Foo.java" to "Features/Base", "a/Bar.java" to "Features/MicrosoftCodeAnalyzer")
        val pages = GhidraJavadoc.unofficialPages(api, setOf("a/Foo.html"), modules)
        assertEquals(
            mapOf(
                "a/Bar" to "Features/MicrosoftCodeAnalyzer",
                "a/Bar.Inner" to "Features/MicrosoftCodeAnalyzer",
                "a/package-summary" to "Features/Base, Features/MicrosoftCodeAnalyzer",
            ),
            pages,
        )
        assertEquals(
            """
            window.ghidraUnofficial = {
              "modules": ["Features/Base, Features/MicrosoftCodeAnalyzer", "Features/MicrosoftCodeAnalyzer"],
              "pages": {
                "a/Bar": 1,
                "a/Bar.Inner": 1,
                "a/package-summary": 0
              }
            };

            """.trimIndent(),
            GhidraJavadoc.pagesScript(pages),
        )
    }
}
