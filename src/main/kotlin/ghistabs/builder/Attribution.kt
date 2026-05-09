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
        val stdMatch = definingCUs.firstNotNullOfOrNull { stdBasename(it) }
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
        val canonicalCu = basename(definingCUs.minOf { it })
        return CategoryPath("/$canonicalCu/instantiations")
    }

    private fun isClean(name: String): Boolean =
        name.isNotEmpty() &&
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
