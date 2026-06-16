package ghistabs.parser

import ghidra.program.model.data.CategoryPath
import ghistabs.diag.StabsDiagnostics

object Attribution {
    /**
     * STD_MARKERS regex now requires stdlib indicators (/usr/, /lib/, /include/) before the marker.
     * The (/ [^/]+)? allows zero or one intermediate directory between prefix and marker.
     * This prevents false positives on project-local directories like /proj/src/c++_helpers/
     * while still matching real stdlib paths like /usr/include/c++/ and /usr/local/mingw/
     */
    private val STD_MARKERS = Regex("""/(usr|lib|include)(/[^/]+)?/(mingw|cygwin|c\+\+|bits)/""")
    private val UNCLEAN_CHARS = Regex("""[<>,:]""")

    /**
     * Project override names: types that should always route to /proj/
     * even if their defining CU matches a stdlib pattern.
     * Used to handle edge cases where stabs data mis-attributes types to stdlib paths.
     */
    private val PROJECT_OVERRIDE_NAMES = setOf("bouniaf")

    private val BUILTIN_NAMES =
        setOf(
            "int",
            "char",
            "short",
            "long",
            "long long",
            "float",
            "double",
            "long double",
            "void",
            "bool",
            "_Bool",
            "signed",
            "unsigned",
            "size_t",
            "ptrdiff_t",
        )

    fun categoryFor(
        typeName: String,
        defSources: Set<SourceFile>,
        diagnostics: StabsDiagnostics? = null,
    ): CategoryPath {
        // 1. Check project override list FIRST (safety net for edge cases)
        if (typeName in PROJECT_OVERRIDE_NAMES) {
            diagnostics?.inc("attribution-override")
            return CategoryPath("/proj/$typeName")
        }

        // 2. Check if ANY definingCU path matches STD_MARKERS. Sort first — the input is a
        //    Set whose iteration order isn't stable across callers, and we MUST land on the
        //    same /std/<header> for every call with the same input or downstream
        //    `dtm.getDataType(category, name)` lookups in ClassBuilder won't match what
        //    materialiseAll registered.
        val sortedDefiningCUs = defSources.sorted()
        val stdMatch = sortedDefiningCUs.firstNotNullOfOrNull { stdBasename(it.filename) }
        if (stdMatch != null) {
            diagnostics?.recordAttributionTrace(
                typeName = typeName,
                definingCUs = defSources,
                matchedCU = sortedDefiningCUs.first { stdBasename(it.filename) != null },
                routedTo = "/std/$stdMatch",
                counter = "attribution-routed-std",
            )
            return CategoryPath("/std/$stdMatch")
        }

        // 3. All-HeaderSource, same filename basename → /headers/<basename>/.
        //    Covers the common case (single defining HeaderSource) AND the
        //    cross-CU header-shared case where multiple HeaderSource entries
        //    point at the same physical header (forward-EXCL D1 may produce
        //    distinct HeaderFile instances for the same filename, but the
        //    routing should still converge). Stays before the single-CU
        //    shortcut so single HeaderSource defs land in `/headers/...`
        //    instead of `/<basename>/` (stabs-canonicalization.md §7.1, D2).
        val headerBasenames = defSources
            .filterIsInstance<SourceFile.HeaderSource>()
            .map { basename(it.filename) }
            .toSet()
        if (headerBasenames.size == 1 && defSources.all { it is SourceFile.HeaderSource }) {
            val headerBase = headerBasenames.single()
            diagnostics?.recordAttributionTrace(
                typeName = typeName,
                definingCUs = defSources,
                matchedCU = sortedDefiningCUs.first(),
                routedTo = "/headers/$headerBase",
                counter = "attribution-routed-headers",
            )
            return CategoryPath("/headers/$headerBase")
        }

        // 4. Single CUSource → /<basename>/.
        if (defSources.size == 1) {
            val cu = defSources.single() as SourceFile.CUSource
            return CategoryPath("/" + basename(cu.filename))
        }

        // 5. Multi-CU decision tree
        if (isClean(typeName)) {
            return CategoryPath("/headers-untracked/$typeName.h")
        }

        // Otherwise: canonical CU is lex-first basename
        val canonicalCu = basename(defSources.minOf { it.filename })
        return CategoryPath("/$canonicalCu/instantiations")
    }

    private fun isClean(name: String): Boolean = name.isNotEmpty() &&
        !UNCLEAN_CHARS.containsMatchIn(name) &&
        !name.startsWith("_") &&
        name !in BUILTIN_NAMES

    private fun stdBasename(path: String): String? {
        val match = STD_MARKERS.find(path) ?: return null
        val startIdx = match.range.last + 1
        if (startIdx >= path.length) return null
        var current = path.substring(startIdx)

        // Skip version-number segments and known intermediate dirs
        val skipNames = setOf("bits", "ext", "tr1", "tr2", "debug", "profile", "parallel")
        while (current.isNotEmpty()) {
            val slash = current.indexOf('/')
            if (slash == -1) break // last segment = basename
            val segment = current.substring(0, slash)
            val rest = current.substring(slash + 1)
            // Skip if pure digits/dots (version) or a known intermediate dir
            if (segment.all { it.isDigit() || it == '.' } || segment in skipNames) {
                current = rest
            } else {
                break
            }
        }
        // current is now either the final path segment or starts with the target dir
        val endIdx = current.indexOf('/')
        val segment = if (endIdx == -1) current else current.substring(0, endIdx)
        val noExt = segment.substringBeforeLast('.')
        return noExt.ifEmpty { segment.ifEmpty { null } }
    }

    private fun basename(path: String): String {
        // Drop directory prefix and extension
        val name = path.substringAfterLast('/')
        val noExt = name.substringBeforeLast('.')
        return noExt.ifEmpty { name }
    }
}
