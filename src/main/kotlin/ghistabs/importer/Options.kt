package ghistabs.importer

import ghidra.framework.options.Options
import ghidra.program.model.listing.Program
import ghistabs.*
import ghistabs.diagnose.Level
import ghistabs.materialize.VfptrModel

const val STABS_ANALYZER_NAME = "Stabs Importer"

class ImportOptions() : OptionContainer() {
    var applyPlateComments: Boolean by PLATE_COMMENTS
    var buildClasses: Boolean by CLASSES
    var shortenTypedefs: Boolean by SHORTEN_TYPEDEFS
    var foldSources: Boolean by FOLD_SOURCES
    var minLogLevel: Level by LOG_LEVEL
    var overlaySection: Boolean by OVERLAY_SECTION
    var vfptrModel: VfptrModel by VFPTR_MODEL
    var sourceRoots: List<String> by SOURCE_ROOTS

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
        val VFPTR_MODEL = EnumOption(
            "Virtual function pointer model",
            "Where a polymorphic class's {vfptr} comes from. INHERITED keeps one on the root of each " +
                "hierarchy, shared through the base subobject — derived slots then sit past the end of " +
                "the root's vftable and virtual calls render as vfptr[N].field. SPLIT_BASE gives every " +
                "polymorphic class its own {vfptr} typed to its own vftable, embedding the primary base " +
                "as that base's fields without the vptr, so virtual calls resolve to named slots.",
            VfptrModel.SPLIT_BASE,
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
            listOf(
                PLATE_COMMENTS,
                CLASSES,
                SHORTEN_TYPEDEFS,
                FOLD_SOURCES,
                LOG_LEVEL,
                OVERLAY_SECTION,
                VFPTR_MODEL,
                SOURCE_ROOTS,
            )

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

    constructor(opts: Options) : this() {
        import(opts)
    }

    constructor(program: Program) : this(
        program.getOptions(Program.ANALYSIS_PROPERTIES).getOptions(STABS_ANALYZER_NAME),
    )

    constructor(config: ImportOptions.() -> Unit) : this() {
        config(this)
    }
}
