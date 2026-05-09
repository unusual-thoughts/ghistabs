package ghistabs.builder

import ghidra.program.model.data.CategoryPath

object Attribution {
    private val STD_MARKERS = Regex("""/(mingw|cygwin|c\+\+|bits)/""")
    private val UNCLEAN_CHARS = Regex("""[<>,:]""")
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
        definingCUs: Set<String>,
    ): CategoryPath {
        // 1. Check if ANY definingCU path matches STD_MARKERS
        val stdMatch = definingCUs.mapNotNull { stdBasename(it) }.firstOrNull()
        if (stdMatch != null) {
            return CategoryPath("/std/$stdMatch")
        }

        // 2. Single CU ending with .h/.hpp/.hh/.H (header)
        if (definingCUs.size == 1) {
            val cu = definingCUs.single()
            if (cu.endsWith(".h") || cu.endsWith(".hpp") || cu.endsWith(".hh") || cu.endsWith(".H")) {
                return CategoryPath("/" + basename(cu))
            }
            // 3. Single CU with .c/.cpp/.cc extension
            if (cu.endsWith(".c") || cu.endsWith(".cpp") || cu.endsWith(".cc")) {
                return CategoryPath("/" + basename(cu))
            }
        }

        // 4. Multi-CU decision tree
        if (isClean(typeName)) {
            return CategoryPath("/headers-untracked/$typeName.h")
        }

        // Otherwise: canonical CU is lex-first basename
        val canonicalCu = basename(definingCUs.sorted().first())
        return CategoryPath("/$canonicalCu/instantiations")
    }

    private fun isClean(name: String): Boolean =
        name.isNotEmpty() &&
            !UNCLEAN_CHARS.containsMatchIn(name) &&
            !name.startsWith("_") &&
            name !in BUILTIN_NAMES

    private fun stdBasename(path: String): String? {
        // Find the STD_MARKERS match and return the last non-empty segment after it
        val match = STD_MARKERS.find(path) ?: return null
        // The matched segment is something like "/c++/" or "/mingw/"
        // After the match, we may have version info (3.4.4) or directly the filename
        val startIdx = match.range.last + 1 // position after the marker
        if (startIdx >= path.length) return null

        val remainder = path.substring(startIdx)
        // Skip version numbers: look for path segments that start with digits and skip to the next segment
        var current = remainder
        while (current.isNotEmpty() && current[0].isDigit()) {
            // Skip until next '/' or end
            val idx = current.indexOf('/')
            if (idx == -1) {
                // Only a version segment, no actual basename after
                return null
            }
            current = current.substring(idx + 1)
        }

        // Now extract the first non-version segment
        val endIdx = current.indexOf('/')
        val segment = if (endIdx == -1) current else current.substring(0, endIdx)
        // Remove extension
        val noExt = segment.substringBeforeLast('.')
        return if (noExt.isNotEmpty()) noExt else segment
    }

    private fun basename(path: String): String {
        // Drop directory prefix and extension
        val name = path.substringAfterLast('/')
        val noExt = name.substringBeforeLast('.')
        return if (noExt.isEmpty()) name else noExt
    }
}
