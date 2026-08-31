package ghidra.util

import ghidra.formats.gfilesystem.FSUtilities
import java.net.URI
import java.net.URISyntaxException

/**
 * `normalizeDwarfPath` as of 11.3, ported. Pure string work over [FSUtilities.normalizeNativePath],
 * which every release has, so the paths — and the DTM categories derived from them — come out
 * identical on either side of the boundary.
 */
object SourceFileUtils {
    @JvmStatic
    fun normalizeDwarfPath(path: String, baseDir: String): String {
        require(baseDir.isNotEmpty() && baseDir.all { it.isLetterOrDigit() || it == '_' }) {
            "baseDir must consist of alphanumeric characters or underscores"
        }
        val based = path.startsWith("./")
        val rooted = if (based) "/$baseDir${path.substring(1)}" else path
        var normalized = try {
            URI("file", null, FSUtilities.normalizeNativePath(rooted), null).normalize().path
        } catch (e: URISyntaxException) {
            throw IllegalArgumentException("path not valid: ${e.message}")
        }
        var dotDots = 0
        while (normalized.startsWith("/..")) {
            normalized = normalized.substring(3)
            dotDots++
        }
        if (dotDots == 0) {
            // The baseDir was unnecessary: the spelling normalised to an absolute path without it.
            if (!based) return normalized
            if (normalized.startsWith("/$baseDir")) return normalized
        }
        // An interior `/../` consumed the baseDir we prepended, so it counts as one of them.
        if (based) dotDots++
        return "/$baseDir${if (dotDots == 0) "" else "_$dotDots"}$normalized"
    }
}
