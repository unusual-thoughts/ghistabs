package ghicpp.stl

import ghidra.program.model.data.Composite
import ghidra.program.model.data.DataTypeManager

/**
 * An archive's classes by a [key] that leaves out how a name is spelled, for the classes a demangler
 * names otherwise than the archive's DWARF did: Ghidra's GNU demangler writes `pair<int_const,int>` and
 * `vector<std::string>` where the DWARF importer filed `pair<int_const,_int>` and
 * `vector<std::basic_string<char,_std::char_traits<char>,_std::allocator<char>_>_>`. A key two of the
 * archive's classes share finds neither.
 */
class StlIndex(archive: DataTypeManager) {
    private val byKey: Map<String, Composite?> = buildMap {
        archive.allComposites.forEach { c ->
            // A program's data type manager lists some types it has deleted.
            if (c.isNotYetDefined || c.isDeleted) return@forEach
            val k = key(c.categoryPath.pathElements.toList() + c.name)
            val seen = get(k)
            put(k, if (k in this && (seen == null || archive.getID(seen) != archive.getID(c))) null else c)
        }
    }

    /** The class at [path], its scopes from the root, however it is spelled; null if none or several. */
    fun find(path: List<String>): Composite? = byKey[key(path)]

    companion object {
        private val ALIASES = StlApplier.gnuAliases()
        private val ALIAS = run {
            val names = ALIASES.keys.sortedByDescending { it.length }.joinToString("|")
            // Spelled as the demangler and the importer do, a space as `_`: `std::string_const`.
            val end = "$|[^A-Za-z0-9_<]|_(?:const|volatile)(?![A-Za-z0-9])|_[*&>,]"
            Regex("(?<![A-Za-z0-9:])(std::(?:__cxx11::)?)($names)(?=$end)")
        }
        private val LEADING_CV = Regex("(?<=^|[<,(]|[<,(]_)(const|volatile)_")
        private val SUFFIX = Regex("(?<![A-Za-z0-9])(\\d+)(?:ull|ul|ll|u|l)(?![A-Za-z0-9])", RegexOption.IGNORE_CASE)

        /**
         * [path] as one C++ name with each alias of [StlApplier.gnuAliases] written out, each leading
         * cv-qualifier moved after its type, and its spaces, underscores and integer suffixes dropped: the
         * importer writes `const T` where the demangler writes `T const`, and `0` where it writes `0ul`.
         */
        @JvmStatic
        fun key(path: List<String>): String {
            val cxx = ALIAS.replace(path.joinToString("::")) { it.groupValues[1] + ALIASES.getValue(it.groupValues[2]) }
            return SUFFIX.replace(trailingCv(cxx).replace('_', ' '), "$1").replace(" ", "")
        }

        /** [cxx] with each `const_T` written `T_const`, T a name with its template arguments. */
        private fun trailingCv(cxx: String): String {
            var out = cxx
            while (true) {
                val m = LEADING_CV.find(out) ?: return out
                val start = m.range.last + 1
                var end = start
                var depth = 0
                while (end < out.length) {
                    val c = out[end]
                    when {
                        c == '<' -> depth++
                        c == '>' && depth > 0 -> depth--
                        depth == 0 && !(c.isLetterOrDigit() || c == '_' || c == ':') -> break
                    }
                    end++
                }
                // A name ends before the `_` the importer puts for the space ahead of a `>` or `,`.
                while (end > start && out[end - 1] == '_') end--
                out = out.substring(0, m.range.first) + out.substring(start, end) + "_" + m.groupValues[1] +
                    out.substring(end)
            }
        }
    }
}
