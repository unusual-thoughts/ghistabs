package ghicpp.stl

import com.google.gson.GsonBuilder
import ghicpp.Access
import ghidra.program.model.data.CategoryPath
import kotlinx.serialization.Serializable
import java.io.File

/** A direct base of a [StdClass]: the base at its archive [path], how the class holds it, and where. */
@Serializable
data class StdBase(val path: String, val access: Access, val isVirtual: Boolean = false, val offset: Long? = null)

/** A virtual function a [StdClass] introduces: its [name], and its [offset] in bytes into the class's vftable. */
@Serializable
data class StdSlot(val offset: Long, val name: String)

/**
 * A class as the runtime's debug info declares it, at its archive [path]: its direct [bases], which its
 * struct alone loses (an empty base takes no bytes, and nothing there says access or virtuality), and the
 * virtual functions it introduces ([slots]), which [StlVftables] lays its vftable off.
 */
@Serializable
data class StdClass(val path: String, val bases: List<StdBase> = emptyList(), val slots: List<StdSlot> = emptyList()) {
    /** Its namespace path: `std`, `basic_streambuf<…>` for `/std/basic_streambuf<…>`. */
    val segments: List<String> get() = CategoryPath(path).pathElements.toList()
}

/**
 * The classes of a standard library archive, whichever ABI's and whatever debug info they come from, which
 * ship beside it as `<archive>.classes.json`. Ghidra's Gson writes and reads them off these classes as they
 * are: the format is the model, with no serializer of its own. [MsvcPdbClasses] reads them off a PDB.
 */
@Serializable
data class StdClasses(val classes: List<StdClass> = emptyList()) {
    fun toJson(): String = GSON.toJson(this) + "\n"

    /** Writes [toJson] to [file]. */
    fun write(file: File) = file.writeText(toJson())

    companion object {
        const val SUFFIX = ".classes.json"
        private val GSON = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()

        fun fromJson(text: String): StdClasses = GSON.fromJson(text, StdClasses::class.java)
    }
}
