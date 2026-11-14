package ghicpp.stl

import ghicpp.Access
import ghidra.framework.options.GProperties
import ghidra.program.model.data.CategoryPath
import ghidra.util.xml.XmlUtilities
import ghidrakt.GPropertiesFormat
import kotlinx.serialization.Serializable
import java.io.File
import java.io.InputStream
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream

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
 * ship beside it as `<archive>.classes.xml.gz`: the model as [GPropertiesFormat] encodes it, the way ghicpp
 * stores its class hierarchy record, saved as GProperties' XML and gzipped (each value carries its type, so
 * the text repeats itself and packs small). [MsvcPdbClasses] reads them off a PDB.
 */
@Serializable
data class StdClasses(val classes: List<StdClass> = emptyList()) {
    /** Writes the classes to [file], gzipped. */
    fun write(file: File) {
        val properties = GProperties(NAME)
        GPropertiesFormat.encode(serializer(), this, properties)
        GZIPOutputStream(file.outputStream()).use { it.write(XmlUtilities.xmlToByteArray(properties.saveToXml())) }
    }

    companion object {
        const val SUFFIX = ".classes.xml.gz"
        private const val NAME = "StdClasses"

        /** Reads what [write] wrote off [input], closing it. */
        fun read(input: InputStream): StdClasses {
            val bytes = GZIPInputStream(input).use { it.readBytes() }
            val properties = GProperties(XmlUtilities.byteArrayToXml(bytes))
            return GPropertiesFormat.decode(serializer(), properties)
        }
    }
}
