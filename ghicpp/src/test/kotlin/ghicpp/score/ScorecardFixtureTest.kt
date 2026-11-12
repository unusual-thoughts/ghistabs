package ghicpp.score

import ghicpp.ClassRecordSource
import ghicpp.analyzers.*
import ghicpp.hierarchy.ClassHierarchy
import ghicpp.hierarchy.ClassHierarchy.MemberKind
import ghicpp.hierarchy.unattachedVirtuals
import ghicpp.ooa.OoFactExporter
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
 * Each score is a counter per attribute (`<attribute>-tp`, `-fp`, `-fn`), checked against
 * `src/test/resources/ghicpp/scorecard/baselines/<case>.json`. The instances behind each `-fp` and `-fn` counter,
 * one `<counter> <instance>` line each, are checked against `<case>.instances.txt` next to it.
 *
 * The test fails when a counter moves or an instance appears or disappears. With `-PignoreBaselines=true` it
 * writes the new baseline to `build/test-output/shifted-baselines/` instead, which CI uploads.
 * `-PregenerateBaselines=true` rewrites the committed baselines. Each case's scorecard, its instances by
 * attribute, and both serialized class views are written to `build/test-output/scorecards/<case>/`.
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
        val out = File(OUTPUT_DIR, case.id).apply { mkdirs() }
        val facts = File(out, "ooanalyzer.facts")
        var slots: Set<Long>? = null
        val subject = snapshotOf(subjectFile, case.compiler, facts, { prepare(case.recovery, runtime) }) {
            if (truth.sameBinary) slots = slotTargets(truth.snapshot.vtables)
        }
        val card = Scorer(truth, subject, slots).score()

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
        checkBaseline(case, card.counters() + (UNATTACHED to subject.unattachedVirtuals.toLong()), card.instanceLines())
        System.getProperty("ooprolog").orEmpty().takeIf { it.isNotEmpty() }?.let { solve(case, truth, facts, File(it)) }
    }

    /**
     * Runs OOAnalyzer's Prolog rules, from Pharos' `share/prolog` at [prolog], over the facts the subject's
     * program gave, and scores the classes they recover as ours are, into `ooanalyzer-scorecard.md` beside
     * ours. Not held to a baseline: what moves it is OOAnalyzer's rules and the facts' fidelity.
     */
    private fun solve(case: ScorecardCase, truth: Truth, facts: File, prolog: File) {
        val out = facts.parentFile
        val results = File(out, "ooanalyzer.results")
        val log = File(out, "ooprolog.log")
        val process = ProcessBuilder(
            "swipl",
            File(prolog, "oorules/ooprolog.pl").path,
            "--oorulespath",
            prolog.path,
            "--facts",
            facts.path,
            "--results",
            results.path,
        ).redirectErrorStream(true).redirectOutput(log).start()
        val done = process.waitFor(OOPROLOG_TIMEOUT_MINUTES, java.util.concurrent.TimeUnit.MINUTES)
        if (!done) process.destroyForcibly()
        assumeTrue(done && results.isFile, "ooprolog gave no results for ${case.id}: see $log")
        val purecalls = PURECALL.findAll(facts.readText()).map { it.groupValues[1].toLong(16) }.toSet()
        val solved = OoResults(results.readText(), purecalls).snapshot(case.subject)
        val card = Scorer(truth, solved).score()
        File(out, "ooanalyzer-scorecard.md").writeText(card.markdown("${case.id}: OOAnalyzer's rules over our facts"))
        File(out, "ooanalyzer-subject.json").writeText(PRETTY.encodeToString(Snapshot.serializer(), solved))
        File(out, "ooanalyzer-counters.json")
            .writeText(PRETTY.encodeToString(COUNTERS, card.counters().toSortedMap()) + "\n")
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
            val snapshot = snapshotOf(bin, compiler, { runtime = runtimeFunctions() })
            TruthFile(snapshot, runtime).also {
                file.parentFile.mkdirs()
                GZIPOutputStream(file.outputStream()).bufferedWriter().use { w ->
                    w.write(COMPACT.encodeToString(TruthFile.serializer(), it) + "\n")
                }
            }
        }
    }

    /** [file] analyzed after [setup], as a [Snapshot]; its OOAnalyzer facts written to [facts] too, if given. */
    private fun snapshotOf(
        file: File,
        compiler: String,
        facts: File? = null,
        setup: Program.() -> Unit,
        analysed: Program.() -> Unit = {},
    ): Snapshot = loadProgram(file, compiler).use { loaded ->
        val program = loaded.program
        program.runTransaction("options") {
            // Runs a Ghidra script on a PE, which the headless harness has no bundle host for.
            program.getOptions(Program.ANALYSIS_PROPERTIES).setBoolean("WindowsResourceReference", false)
        }
        program.setup()
        analyzeAll(program)
        program.analysed()
        facts?.bufferedWriter()?.use { OoFactExporter(program).write(it) }
        program.snapshot(file.name)
    }

    /** The addresses that the words of the truth's [vtables] hold, read from this program, the binary they describe. */
    private fun Program.slotTargets(vtables: List<VtableExtent>): Set<Long> = vtables.flatMapTo(HashSet()) { v ->
        val ptr = defaultPointerSize.toLong()
        (v.start until v.end step ptr).mapNotNull { at ->
            runCatching { pointerAt(addressFactory.defaultAddressSpace.getAddress(at)) }.getOrNull()?.offset
        }
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

    private fun checkBaseline(case: ScorecardCase, counters: Map<String, Long>, instances: List<String>) {
        val committed = File(BASELINE_DIR, "${case.id}.json")
        val committedInstances = File(BASELINE_DIR, "${case.id}.instances.txt")
        val text = PRETTY.encodeToString(COUNTERS, counters.toSortedMap()) + "\n"
        val instanceText = instances.joinToString("") { "$it\n" }
        if (System.getProperty("regenerateBaselines") == "true") {
            committed.parentFile.mkdirs()
            committed.writeText(text)
            committedInstances.writeText(instanceText)
            return
        }
        assumeTrue(committed.isFile, "no committed baseline for ${case.id}")
        val baseline = COMPACT.decodeFromString(COUNTERS, committed.readText())
        val baselineInstances = committedInstances.takeIf { it.isFile }?.readLines().orEmpty()
        if (baseline == counters && baselineInstances == instances) return
        SHIFTED_DIR.mkdirs()
        File(SHIFTED_DIR, "scorecard-${case.id}.json").writeText(text)
        File(SHIFTED_DIR, "scorecard-${case.id}.instances.txt").writeText(instanceText)
        val drift = (baseline.keys + counters.keys).toSortedSet()
            .filter { baseline[it] != counters[it] }
            .map { "$it: ${baseline[it]} -> ${counters[it]}" } +
            (instances - baselineInstances.toSet()).map { "+ $it" } +
            (baselineInstances - instances.toSet()).map { "- $it" }
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
        private val PURECALL = Regex("""^purecall\(0x([0-9a-f]+)\)\.""", RegexOption.MULTILINE)
        private const val OOPROLOG_TIMEOUT_MINUTES = 30L

        /** The counter of the subject's virtual functions in no class, trivial stubs left out: fewer is better. */
        private const val UNATTACHED = "vfunctions-unattached"

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
            VtableExtent(m.address.offset, nextSymbolAfter(m.address).offset, cls.id)
        }
    }.distinct()
    return Snapshot(fixture, hierarchy, fields, vtables, hierarchy.unattachedVirtuals(this).size)
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
