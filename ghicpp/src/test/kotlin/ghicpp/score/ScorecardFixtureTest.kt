package ghicpp.score

import ghicpp.ClassRecordSource
import ghicpp.analyzers.*
import ghicpp.hierarchy.ClassHierarchy
import ghicpp.hierarchy.ClassHierarchy.MemberKind
import ghicpp.score.Truth.Companion.withBasesOf
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.framework.options.OptionType
import ghidra.program.model.address.Address
import ghidra.program.model.data.Array
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Structure
import ghidra.program.model.data.TypeDef
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghidrakt.*
import ghidrakt.test.TestBinaries
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.io.File
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream

/**
 * How a subject binary's classes are recovered: off its RTTI, the default analysis, or as if it had none,
 * every RTTI analyzer off and the vftables found from pointer tables instead.
 */
enum class Recovery { RTTI, NO_RTTI }

/**
 * One scorecard: [subject], a binary with no symbols, recovered by [recovery], scored against what is known
 * of its classes. [twin] is the binary it was stripped from, so the same addresses; [source] a build of the
 * same source with stabs, for a subject with no twin, or whose twin has symbols but no stabs, to say its
 * bases. [labelled] names the runtime functions the heuristics look for (operator new and delete, memset,
 * the pure virtual stub) before the analysis, at the twin's addresses for them.
 */
data class ScorecardCase(
    val subject: String,
    val recovery: Recovery,
    val twin: String? = null,
    val source: String? = null,
    val labelled: Boolean = false,
    /** The [twin] is the subject itself, its classes recovered off its RTTI: their vtables known, their methods not. */
    val twinRecovered: Boolean = false,
    /** The compiler spec the subject loads with: `windows` for an MSVC build, whose class analyzer wants it. */
    val compiler: String = "gcc",
    val dir: File = TestBinaries.DIR,
) {
    /** The twin loads as the subject does when it is the subject; a stabs or symbols build is gcc's. */
    val twinCompiler: String get() = if (twinRecovered) compiler else "gcc"

    val id: String get() =
        subject.substringBefore('.') + "-" + recovery.name.lowercase().replace('_', '-') +
            if (labelled) "-labelled" else ""

    override fun toString() = id
}

/** A truth binary's [snapshot], as committed, with the runtime functions its symbols name, at their offsets. */
@Serializable
data class TruthFile(val snapshot: Snapshot, val runtime: Map<String, Long> = emptyMap())

/**
 * The C++ class recovery's integration entrypoint: scores what it makes of each of [cases] against ground
 * truth, and holds every score to its baseline.
 *
 * The truth is committed, one gzipped JSON per truth binary under `src/test/resources/ghicpp/scorecard/truth/`: the
 * class view a stabs import, or a binary's own symbols, gives its twin. So scoring needs nothing but the
 * subject binaries and this package; `-PregenerateTruth=true` rebuilds the files from the truth binaries,
 * which takes the stabs importer. Review their diff as you would a fixture's.
 *
 * Each score is a counter per attribute (`<attribute>-tp`, `-fp`, `-fn`), held to
 * `src/test/resources/ghicpp/scorecard/baselines/<case>.json`. A counter that moves fails the test, or under
 * `-PignoreBaselines=true` only writes the new baseline to `build/test-output/shifted-baselines/`, which CI
 * uploads; `-PregenerateBaselines=true` rewrites the committed ones. Each case's scorecard, its findings and
 * both serialized class views land in `build/test-output/scorecards/<case>/`.
 */
@Tag("integration")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class ScorecardFixtureTest : AbstractGhidraHeadlessIntegrationTest() {
    abstract fun cases(): List<ScorecardCase>

    // One read, or generation, of each truth for every case scored against it.
    private val truths = mutableMapOf<String, TruthFile>()

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    fun scorecard(case: ScorecardCase) {
        val subjectFile = File(case.dir, case.subject)
        assumeTrue(accepts(case.subject), "excluded by -Pfixture")
        assumeTrue(subjectFile.isFile, "${case.subject} is not on disk")
        val truth = truthFor(case)
        val runtime = case.twin?.takeIf { case.labelled }?.let { truthOf(case, it).runtime }.orEmpty()
        assumeTrue(!case.labelled || runtime.isNotEmpty(), "the twin names no runtime function to label")
        val subject = snapshotOf(subjectFile, case.compiler) { prepare(case.recovery, runtime) }
        val card = Scorer(truth, subject).score()

        val out = File(OUTPUT_DIR, case.id).apply { mkdirs() }
        val against = listOfNotNull(case.twin, case.source).joinToString(" + ")
        val labels = runtime.entries.joinToString("\n", "\n## Labelled before the analysis\n\n", "\n") {
            "- `${it.key}` at %x".format(it.value)
        }
        File(out, "scorecard.md").writeText(
            card.markdown("${case.id}: ${case.subject} against $against") +
                labels.takeIf { runtime.isNotEmpty() }.orEmpty(),
        )
        File(out, "subject.json").writeText(PRETTY.encodeToString(Snapshot.serializer(), subject))
        File(out, "truth.json").writeText(PRETTY.encodeToString(Snapshot.serializer(), truth.snapshot))
        checkBaseline(case, card.counters())
    }

    private fun truthFor(case: ScorecardCase): Truth {
        val twin = case.twin?.let { truthOf(case, it).snapshot }
        val source = case.source?.let { truthOf(case, it, asSource = true).snapshot }
        return when {
            twin != null && source == null ->
                Truth(twin, Truth.describedScope(twin.hierarchy), sameBinary = true, sameLayout = true)

            twin != null && source != null -> {
                val sourceScope = Truth.describedScope(source.hierarchy)
                val names = sourceScope.mapNotNull { source.hierarchy[it]?.qualifiedName }.toSet()
                val scope = twin.hierarchy.classes.filter { it.qualifiedName in names }.mapTo(HashSet()) { it.id }
                val described = twin.withBasesOf(source.hierarchy, sourceScope)
                Truth(described, scope, sameBinary = true, sameLayout = false, membersKnown = !case.twinRecovered)
            }

            source != null ->
                Truth(source, Truth.describedScope(source.hierarchy), sameBinary = false, sameLayout = false)

            else -> error("${case.id} has neither a twin nor a source to score against")
        }
    }

    /**
     * The committed truth [binary] gives, or with `-PregenerateTruth=true` (or none committed yet) the one it
     * gives now, written back. A twin that is the subject's own RTTI recovery is named after that.
     */
    private fun truthOf(case: ScorecardCase, binary: String, asSource: Boolean = false): TruthFile {
        val recovered = case.twinRecovered && !asSource
        val name = binary.substringBefore('.') + if (recovered) "-rtti" else ""
        val compiler = if (asSource) "gcc" else case.twinCompiler
        return truths.getOrPut(name) {
            // Gzipped: a Crypto++ build's truth is megabytes of JSON.
            val file = File(TRUTH_DIR, "$name.json.gz")
            if (file.isFile && System.getProperty("regenerateTruth") != "true") {
                val text = GZIPInputStream(file.inputStream()).bufferedReader().use { it.readText() }
                return@getOrPut COMPACT.decodeFromString(TruthFile.serializer(), text)
            }
            val bin = File(case.dir, binary)
            assumeTrue(bin.isFile, "$binary is not on disk, and no truth is committed for it")
            var runtime = emptyMap<String, Long>()
            val snapshot = snapshotOf(bin, compiler) { runtime = runtimeFunctions() }
            TruthFile(snapshot, runtime).also {
                file.parentFile.mkdirs()
                GZIPOutputStream(file.outputStream()).bufferedWriter().use { w ->
                    w.write(COMPACT.encodeToString(TruthFile.serializer(), it) + "\n")
                }
            }
        }
    }

    private fun snapshotOf(file: File, compiler: String, setup: Program.() -> Unit): Snapshot =
        loadProgram(file, compiler).use { loaded ->
            val program = loaded.program
            program.runTransaction("options") {
                // Runs a Ghidra script on a PE, which the headless harness has no bundle host for.
                program.getOptions(Program.ANALYSIS_PROPERTIES).setBoolean("WindowsResourceReference", false)
            }
            program.setup()
            analyzeAll(program)
            program.snapshot(file.name)
        }

    private fun Program.prepare(recovery: Recovery, runtime: Map<String, Long>) {
        // A subject that still carries stabs (a `_stripped` PE keeps them) is recovered as if it had none.
        runTransaction("strip") {
            for (name in listOf(".stab", ".stabstr")) {
                memory.getBlock(name)?.let { memory.removeBlock(it, TaskMonitor.DUMMY) }
            }
        }
        check(!ClassRecordSource.describedElsewhere(this)) { "$name is still described by something else" }
        if (recovery == Recovery.NO_RTTI) {
            // The analyzers' options are registered only once the manager has been asked for them.
            AutoAnalysisManager.getAnalysisManager(this).initializeOptions()
            val analysis = getOptions(Program.ANALYSIS_PROPERTIES)
            val rttiAnalyzers = analysis.optionNames.filter { name ->
                analysis.getType(name) == OptionType.BOOLEAN_TYPE && '.' !in name &&
                    (name in OUR_RTTI_ANALYZERS || "RTTI" in name)
            }
            runTransaction("no rtti") {
                rttiAnalyzers.forEach { analysis.setBoolean(it, false) }
                analysis.setBoolean(GenericVftableAnalyzer.NAME, true)
            }
        }
        if (runtime.isNotEmpty()) {
            runTransaction("label runtime") {
                for ((name, offset) in runtime) {
                    symbolTable.createLabel(imageBase.getNewAddress(offset), name, SourceType.USER_DEFINED).setPrimary()
                }
            }
        }
    }

    /** Where the runtime functions the heuristics go by name sit, while the loader's symbols still name them. */
    private fun Program.runtimeFunctions(): Map<String, Long> = RUNTIME_FUNCTIONS.mapNotNull { name ->
        // A PE's COFF symbols keep the leading underscore of the C name.
        listOf(name, "_$name").firstNotNullOfOrNull { spelled ->
            symbolTable.getSymbols(spelled).iterator().asSequence()
                .firstOrNull { !it.isExternal && memory.getBlock(it.address)?.isExecute == true }
        }?.let { name to it.address.offset }
    }.toMap()

    private fun analyzeAll(program: Program) {
        val mgr = AutoAnalysisManager.getAnalysisManager(program)
        mgr.initializeOptions()
        mgr.reAnalyzeAll(null)
        program.runTransaction("auto-analyze") {
            mgr.startAnalysis(TaskMonitor.DUMMY)
            mgr.waitForAnalysis(null, TaskMonitor.DUMMY)
        }
    }

    private fun checkBaseline(case: ScorecardCase, counters: Map<String, Long>) {
        val committed = File(BASELINE_DIR, "${case.id}.json")
        val text = PRETTY.encodeToString(COUNTERS, counters.toSortedMap()) + "\n"
        if (System.getProperty("regenerateBaselines") == "true") {
            committed.parentFile.mkdirs()
            committed.writeText(text)
            return
        }
        assumeTrue(committed.isFile, "no committed baseline for ${case.id}")
        val baseline = COMPACT.decodeFromString(COUNTERS, committed.readText())
        if (baseline == counters) return
        File(SHIFTED_DIR, "scorecard-${case.id}.json").apply { parentFile.mkdirs() }.writeText(text)
        val drift = (baseline.keys + counters.keys).toSortedSet()
            .filter { baseline[it] != counters[it] }
            .map { "$it: ${baseline[it]} -> ${counters[it]}" }
        if (System.getProperty("ignoreBaselines") != "true") {
            assertEquals(emptyList<String>(), drift, "${case.id} scorecard moved")
        }
    }

    companion object {
        val OUTPUT_DIR = File("build/test-output/scorecards")
        private val SHIFTED_DIR = File("build/test-output/shifted-baselines")
        private val TRUTH_DIR = File("src/test/resources/ghicpp/scorecard/truth")
        private val BASELINE_DIR = File("src/test/resources/ghicpp/scorecard/baselines")
        private val PRETTY = Json { prettyPrint = true }
        private val COMPACT = Json { ignoreUnknownKeys = true }
        private val COUNTERS = MapSerializer(String.serializer(), Long.serializer())

        /** `-Pfixture=<subject>[,…]` narrows the cases to those subjects. */
        private fun accepts(subject: String) = System.getProperty("fixtureFilter").orEmpty()
            .split(',').map(String::trim).filter(String::isNotEmpty).let { it.isEmpty() || subject in it }

        private val OUR_RTTI_ANALYZERS = setOf(
            ItaniumClassAnalyzer.NAME,
            MsvcClassAnalyzer.NAME,
            RttiSymbolAnalyzer.NAME,
            TypeinfoLayoutAnalyzer.NAME,
            VirtualBaseAnalyzer.NAME,
            VtableSweepAnalyzer.NAME,
        )

        /** Operator new and delete, scalar and array, 32- and 64-bit; memset; the pure virtual stubs. */
        val RUNTIME_FUNCTIONS = listOf(
            "_Znwj", "_Znwm", "_Znaj", "_Znam", "_ZdlPv", "_ZdaPv", "_ZdlPvj", "_ZdlPvm",
            "memset", "__cxa_pure_virtual", "_purecall",
        )
    }
}

/** This program's [Snapshot]: its class view, each class's struct's leaf fields, its vtables' extents. */
fun Program.snapshot(fixture: String): Snapshot {
    val hierarchy = ClassHierarchy.of(this, ClassRecordSource.describedElsewhere(this))
    val fields = hierarchy.classes.mapNotNull { cls ->
        val struct = cls.structId?.let(dataTypeManager::getDataType) as? Structure ?: return@mapNotNull null
        struct.takeUnless { it.isZeroLength }?.let { cls.id to leafFields(it) }
    }.toMap()
    val vtables = hierarchy.classes.flatMap { cls ->
        cls.members.filter { it.kind == MemberKind.VTABLE && it.library == null }.map { m ->
            val at = addressFactory.getAddress(m.address)
            VtableExtent(at.offset, nextSymbolAfter(at).offset, cls.id)
        }
    }.distinct()
    return Snapshot(fixture, hierarchy, fields, vtables)
}

private fun Program.nextSymbolAfter(at: Address): Address {
    val end = memory.getBlock(at)?.end ?: at
    return symbolTable.getPrimarySymbolIterator(at.next() ?: at, true).iterator().asSequence()
        .map { it.address }.firstOrNull { it > at }?.takeIf { it <= end } ?: end.next() ?: end
}

/** [struct]'s fields, offset to size, every nested struct (a base, a member object) laid out in its place. */
private fun leafFields(struct: Structure, base: Long = 0, into: MutableMap<Long, Int> = sortedMapOf()): Map<Long, Int> {
    for (c in struct.definedComponents) {
        val type = c.dataType.unwrapped()
        if (type is Structure && !type.isZeroLength) {
            leafFields(type, base + c.offset, into)
        } else if (c.length > 0 && !(type is Array && type.numElements == 0)) {
            into[base + c.offset] = c.length
        }
    }
    return into
}

private fun DataType.unwrapped(): DataType = (this as? TypeDef)?.baseDataType?.unwrapped() ?: this
