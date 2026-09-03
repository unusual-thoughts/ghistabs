package ghistabs.importer

import docking.widgets.filechooser.GhidraFileChooserMode
import docking.widgets.filechooser.GhidraFileChooserPanel
import ghidra.app.util.Option
import ghidra.app.util.OptionException
import ghidra.framework.options.OptionType
import ghidra.framework.options.Options
import ghidra.program.model.listing.Program
import ghistabs.DirectoryListEditor
import ghistabs.diagnose.Level
import ghistabs.runTransaction
import java.awt.Component
import java.beans.PropertyEditor
import java.util.function.Supplier
import kotlin.properties.PropertyDelegateProvider
import kotlin.reflect.KProperty

const val STABS_ANALYZER_NAME = "Stabs Importer"

data class ImportOptions(
    val applyPlateComments: Boolean = PLATE_COMMENTS.default,
    val buildClasses: Boolean = CLASSES.default,
    val shortenTypedefs: Boolean = SHORTEN_TYPEDEFS.default,
    val foldSources: Boolean = FOLD_SOURCES.default,
    val minLogLevel: Level = LOG_LEVEL.default,
    val overlaySection: Boolean = OVERLAY_SECTION.default,
    val sourceRoots: List<String> = SOURCE_ROOTS.default,
) {
    companion object {
        val STABS_DONE = BoolOption("Stabs Imported", "Stabs Import already attempted.", false)
        val OVERLAY_DONE = BoolOption("Stabs Overlaid", "Stab structs already overlaid.", false)
        val SHORTENED_DONE = BoolOption(
            "Stabs Typedefs Shortened",
            "Stabs import ran with typedef shortening enabled.",
            false,
        )

        val PLATE_COMMENTS = BoolOption(
            "Apply scope plate comments",
            "Apply plate comments at lexical scopes when LBRAC/RBRAC info is present.",
            true,
        )
        val CLASSES = BoolOption(
            "Reconstruct C++ classes",
            "Reconstruct C++ classes: class namespaces, member methods (this-typed via __thiscall), " +
                "and <Class>_vftable structs applied at _ZTV for virtual dispatch. Off leaves plain " +
                "structs — member calls lose their this/args and virtual calls stay unresolved.",
            true,
        )
        val SHORTEN_TYPEDEFS = BoolOption(
            "Shorten templated names via typedefs",
            "Rewrite template arguments onto their shorter typedef aliases " +
                "(vector<basic_string<char, …>, …> → vector<string>), recursively. Renames the parent " +
                "datatype itself, so is less faithful to the compiled/mangled type names. " +
                "A type that is itself a typedef's target is left alone.",
            false,
        )
        val FOLD_SOURCES = BoolOption(
            "Fold source-file spellings",
            "Fold two gcc spellings of one physical header (full include path vs bare " +
                "#include \"x.h\") onto one rendered output file, by unique basename.",
            true,
        )
        val LOG_LEVEL = EnumOption(
            "Minimum log level",
            "Minimum level for MessageLog diagnostic output (bookmarks and counters are unaffected).",
            Level.INFO,
        )
        val OVERLAY_SECTION = BoolOption(
            "Overlay .stab section structs",
            "Overlay a decoded StabRecord struct on every .stab entry (refs into .stabstr and back to code/data).",
            true,
        )

        val SOURCE_ROOTS = SerializedOption(
            "Source roots",
            "Local checkouts of the sources this binary was built from, ';'-separated. Each recorded " +
                "source directory found under a root is registered as a directory transform (Source Files " +
                "and Transforms), so paths resolve to real files. Read at import time only: adding a root " +
                "later needs a re-import, though a transform added in the dialog is picked up immediately.",
            emptyList(),
            "",
            { str -> str.split(';').map { it.trim() }.filter { it.isNotEmpty() } },
            { it.joinToString(";") },
        ) { DirectoryListEditor("Choose source root(s)") }

        val IMPORT_OPTIONS =
            listOf(PLATE_COMMENTS, CLASSES, SHORTEN_TYPEDEFS, FOLD_SOURCES, LOG_LEVEL, OVERLAY_SECTION, SOURCE_ROOTS)

        val Program.isStabsDone get() = this[STABS_DONE]

        fun Program.markStabsDone(value: Boolean) {
            this[STABS_DONE] = value
        }

        /**
         * Whether the import that produced this program shortened its templated datatypes. Recorded
         * rather than re-read from the analyzer options, which say what is *set* now — a render run
         * later from the GUI would otherwise pick up a toggle made after the import and spell types
         * one way in the declarations it builds from the AST and the other in decompiled code.
         */
        val Program.stabsTypedefsShortened get() = this[SHORTENED_DONE]

        fun Program.markStabsTypedefsShortened(value: Boolean) {
            this[SHORTENED_DONE] = value
        }

        val Program.isOverlayDone get() = this[OVERLAY_DONE]

        fun Program.markOverlayDone() {
            this[OVERLAY_DONE] = true
        }

        fun Options.registerStabs() {
            for (opt in IMPORT_OPTIONS) {
                opt.register(this)
            }
        }
    }

    constructor(opts: Options) : this(
        applyPlateComments = opts[PLATE_COMMENTS],
        buildClasses = opts[CLASSES],
        shortenTypedefs = opts[SHORTEN_TYPEDEFS],
        foldSources = opts[FOLD_SOURCES],
        minLogLevel = opts[LOG_LEVEL],
        overlaySection = opts[OVERLAY_SECTION],
        sourceRoots = opts[SOURCE_ROOTS],
    )

    constructor(program: Program) : this(
        program.getOptions(Program.ANALYSIS_PROPERTIES).getOptions(STABS_ANALYZER_NAME),
    )
}

/**
 * One declaration — name, description, default, and how the value crosses each API boundary — for an
 * option Ghidra otherwise makes you spell three times: to register it, to read it, to write it.
 *
 * Two unrelated APIs are in play. Analyzers and program info use [Options] (string-keyed, typed
 * getters); exporters take a list of [Option], a different class that carries its own value.
 * [valueOf]/[read] are that second boundary.
 */
abstract class StabOption<T : Any>(val name: String, val desc: String, val default: T) :
    PropertyDelegateProvider<StabOption.Set, StabOption<T>.Bound> {
    abstract fun get(options: Options): T
    abstract fun set(options: Options, value: T)
    abstract fun read(option: Option): T
    open fun register(options: Options) = options.registerOption(
        name,
        default,
        null,
        desc,
    )

    inner class Bound {
        private var value = default
        fun export() = valueOf(value)
        fun import(edited: Option) {
            value = read(edited)
        }

        val option get() = this@StabOption
        operator fun getValue(thisRef: Any?, property: KProperty<*>) = value
    }

    interface Set {
        fun <T : Any> bind(option: StabOption<T>): StabOption<T>.Bound
    }

    /** This option carrying [value], in the form an exporter hands the dialog. */
    open fun valueOf(value: T): Option = Option(name, value)
    override operator fun provideDelegate(thisRef: Set, property: KProperty<*>) = thisRef.bind(this)
}

private fun StabOption<*>.invalid(option: Option) = OptionException("Invalid value for option $name: ${option.value}")
operator fun <T : Any> Options.get(o: StabOption<T>) = o.get(this)
operator fun <T : Any> Options.set(o: StabOption<T>, value: T) = o.set(this, value)

/**
 * [cat] defaults to the program-info bucket, where the done-flags live; an analyzer option is in
 * `ANALYSIS_PROPERTIES → <analyzer name>` and reading it from the default here would silently answer
 * with the option's default instead. [ImportOptions] takes that bucket once, in its constructor.
 */
operator fun <T : Any> Program.get(o: StabOption<T>, cat: String = Program.PROGRAM_INFO) = getOptions(cat)[o]

/** Opens its own transaction, and nests inside an open one — the outermost governs the commit. */
operator fun <T : Any> Program.set(o: StabOption<T>, cat: String = Program.PROGRAM_INFO, value: T) =
    runTransaction("Stabs: set ${o.name} option") {
        getOptions(cat)[o] = value
    }

class BoolOption(name: String, desc: String, default: Boolean) : StabOption<Boolean>(name, desc, default) {
    override fun get(options: Options) = options.getBoolean(name, default)
    override fun set(options: Options, value: Boolean) = options.setBoolean(name, value)
    override fun read(option: Option) = option.value as? Boolean ?: throw invalid(option)
}

class EnumOption<T : Enum<T>>(name: String, desc: String, default: T) : StabOption<T>(name, desc, default) {
    override fun get(options: Options): T = options.getEnum(name, default)
    override fun set(options: Options, value: T) = options.setEnum(name, value)

    // The enum's own class, taken off the default: the type parameter is erased by now.
    override fun read(option: Option): T = default.javaClass.cast(option.value) ?: throw invalid(option)
}

class SerializedOption<T : Any>(
    name: String,
    desc: String,
    default: T,
    val defaultString: String,
    val fromString: (String) -> T,
    val asString: (T) -> String,
    val editor: Supplier<PropertyEditor>,
) : StabOption<T>(name, desc, default) {
    override fun get(options: Options): T = fromString(options.getString(name, defaultString))
    override fun set(options: Options, value: T) = options.setString(name, asString(value))
    override fun read(option: Option): T = fromString(option.value as? String ?: throw invalid(option))
    override fun valueOf(value: T): Option = Option(name, asString(value))
    override fun register(options: Options) = options.registerOption(
        name,
        OptionType.STRING_TYPE,
        defaultString,
        null,
        desc,
        editor,
    )
}

/**
 * A single directory. Exported as an [DirectoryOption.Opt] so it renders as a directories-only
 * chooser — the export dialog's own browse button is `FILES_ONLY` and out of reach.
 */
class DirectoryOption(name: String, desc: String) : StabOption<String>(name, desc, "") {
    override fun get(options: Options): String = options.getString(name, default)
    override fun set(options: Options, value: String) = options.setString(name, value)
    override fun read(option: Option) = (option.value as? String).orEmpty().trim()
    override fun valueOf(value: String) = Opt(value)

    /**
     * The [Option] behind [DirectoryOption]: the component holds the value and [getValue] reads it
     * back out, the shape [ghidra.app.util.exporter.IntelHexExporter]'s record-size option uses. Built on
     * first display rather than in the constructor, so a headless export never touches Swing.
     */
    inner class Opt(private val initial: String) : Option(name, initial) {
        private var panel: GhidraFileChooserPanel? = null

        override fun getCustomEditorComponent(): Component = panel ?: GhidraFileChooserPanel(
            name,
            "Stabs.LastExportDirectory",
            initial,
            false,
            GhidraFileChooserPanel.OUTPUT_MODE,
        ).apply { setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY) }.also { panel = it }

        override fun getValue(): Any = panel?.fileName?.trim() ?: initial
        override fun getValueClass(): Class<*> = String::class.java
        override fun copy(): Option = Opt(value as String)
    }
}

class StabOptions :
    ArrayList<StabOption<*>.Bound>(),
    StabOption.Set {
    override fun <T : Any> bind(option: StabOption<T>): StabOption<T>.Bound = option.Bound().also { this += it }

    /** Takes the dialog's edits back. An unknown name is a wiring bug, not user input. */
    fun export() = map { it.export() }
    fun import(options: List<Option>) = options.forEach { edited ->
        firstOrNull { it.option.name == edited.name }?.import(edited)
            ?: throw OptionException("Unknown option: ${edited.name}")
    }
}
