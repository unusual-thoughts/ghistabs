package ghicpp.stl

import generic.jar.ResourceFile
import ghidra.framework.Application
import ghidra.program.model.data.FileDataTypeManager
import java.io.File

/**
 * A family of standard library archives ghicpp ships, one per runtime build, in the extension's
 * `data/typeinfo/<[dir]>`, where Ghidra lists them with its own archives, so the types a program takes
 * from one stay linked to it; a build that only has ghicpp's jar (the ghistabs extension's tests, say)
 * uses the copies in the jar. Beside each `<name>.gdt` may be its classes ([StdClasses.SUFFIX]).
 */
class StlArchives(private val dir: String, val bundled: Set<String>) {
    fun open(name: String): FileDataTypeManager {
        require(name in bundled) { "no bundled archive $name" }
        val file = shipped("$name.gdt") ?: ResourceFile(copyOut("$name.gdt"))
        return FileDataTypeManager.openFileArchive(file, false)
    }

    /** The classes of archive [name], off the debug info it was built from; empty when none ship. */
    fun classes(name: String): List<StdClass> {
        require(name in bundled) { "no bundled archive $name" }
        val file = "$name${StdClasses.SUFFIX}"
        val text = shipped(file)?.inputStream?.use { String(it.readBytes(), Charsets.UTF_8) }
            ?: resource(file)?.use { String(it.readBytes(), Charsets.UTF_8) }
            ?: return emptyList()
        return StdClasses.fromJson(text).classes
    }

    private fun shipped(file: String) =
        runCatching { Application.findDataFileInAnyModule("typeinfo/$dir/$file") }.getOrNull()?.takeIf { it.exists() }

    private fun resource(file: String) = StlArchives::class.java.getResourceAsStream("/ghicpp/stl/$dir/$file")

    private val temp by lazy {
        File(System.getProperty("java.io.tmpdir"), "ghicpp-stl-${System.getProperty("user.name")}/$dir")
            .apply { mkdirs() }
    }

    private fun copyOut(name: String): File {
        val bytes = checkNotNull(resource(name)) { "missing resource $name" }.use { it.readBytes() }
        val file = File(temp, name)
        if (!file.isFile || !file.readBytes().contentEquals(bytes)) {
            val tmp = File.createTempFile(name, ".tmp", temp)
            tmp.writeBytes(bytes)
            if (!tmp.renameTo(file)) {
                file.delete()
                check(tmp.renameTo(file)) { "cannot write $file" }
            }
        }
        return file
    }
}
