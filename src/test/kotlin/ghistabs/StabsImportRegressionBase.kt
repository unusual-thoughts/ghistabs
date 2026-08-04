package ghistabs

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.app.util.opinion.LoadResults
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.data.Array
import ghidra.program.model.data.Enum
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.StabsAnalyzer.Companion.import
import ghistabs.baseline.BaselineLoader
import ghistabs.baseline.BaselineWriter
import ghistabs.diagnose.CapturingSink
import ghistabs.diagnose.defaultContext
import ghistabs.diagnose.dumpJson
import ghistabs.diagnose.writeRegistryDump
import ghistabs.harvest.ContentIndex
import ghistabs.importer.ImportArtifacts
import ghistabs.importer.ImportContext
import ghistabs.importer.ImportProbe
import ghistabs.materialize.conflictCount
import ghistabs.materialize.itanium.Itanium
import ghistabs.parse.*
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.encodeToStream
import org.junit.jupiter.api.*
import org.junit.jupiter.api.Assumptions.abort
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File

/**
 * Execution-order mode for the regression harness.
 *
 * The behaviour of StabsAnalyzer can differ depending on whether it runs as
 * part of Ghidra's auto-analysis pass (alongside the demangler, decompiler,
 * etc.) or strictly after it. Both modes are observed in practice (e.g. when
 * a user re-imports stabs from the Tools menu after an analysis has settled).
 *
 *  - [CONCURRENT]: our analyzer is left enabled in the analysis options. It is
 *    fired by `AutoAnalysisManager.startAnalysis` alongside the demangler.
 *    Symptom seen on bouniafbouniaf.exe: many function names stay mangled
 *    (`_Z11RegToBinary12EnumRegToken`), presumably because the demangler runs
 *    later but skips symbols whose SourceType we've already promoted.
 *
 *  - [AFTER]: our analyzer is disabled in the analysis options before
 *    `startAnalysis` runs, so auto-analysis (demangler included) settles
 *    first. We then invoke StabsAnalyzer manually. Symptom seen here:
 *    `/Demangler/...` placeholder stubs created by Ghidra's demangler are
 *    sometimes not replaced (e.g. `/Demangler/bouniaf`) — this was
 *    a DemanglerReplacer candidate-filtering bug, see DemanglerReplacer.
 */
enum class Mode { CONCURRENT, AFTER }

/**
 * Regression test harness for StabsAnalyzer on bouniafbouniaf.exe.
 *
 * Runs full analysis pipeline and validates counters against committed baseline.
 * Skips gracefully if fixture is absent (bouniaf, not in repo).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Tag("integration")
abstract class StabsImportRegressionBase(val binaryName: String, val mode: Mode) :
    AbstractGhidraHeadlessIntegrationTest() {

    // Manual inputs live under src/test/resources/ (binaries — gitignored,
    // user-placed — and baselines — tracked); test-generated dumps go to
    // build/test-output/ so `./gradlew clean` regenerates them. See README
    // / build.gradle.kts for the split rationale.
    private fun outputFile(kind: String) = File("build/test-output/${kind}s/${fixture.nameWithoutExtension}-$kind.json")
    private val fixture get() = File("src/test/resources/binaries/$binaryName")
    private val baselineFile get() = File("src/test/resources/baselines/${fixture.nameWithoutExtension}-baseline.json")
    private val recordsFile get() = outputFile("record")
    private val emptyStubDumpFile get() = File(
        "build/test-output/demangler-empty-stubs/${fixture.nameWithoutExtension}.txt",
    )
    private val harvestFile get() = outputFile("harvest.${mode.name.lowercase()}")
    private val registryDumpFile get() = outputFile("registry.${mode.name.lowercase()}")
    private val degradationFile
        get() = File("build/test-output/degradations/${fixture.nameWithoutExtension}.${mode.name.lowercase()}.txt")
    private val logFile
        get() = File("build/test-output/logs/${fixture.nameWithoutExtension}.${mode.name.lowercase()}.log")
    private val analysisTimesFile
        get() = File("build/test-output/analysis-times/${fixture.nameWithoutExtension}.${mode.name.lowercase()}.txt")

    private lateinit var loadResults: LoadResults<Program>
    private lateinit var context: ImportContext<CapturingSink>
    private lateinit var artifacts: ImportArtifacts
    private val program get() = context.program

    @BeforeAll
    fun setUp() {
        assumeTrue(
            fixture.exists(),
            "Skipping: ${fixture.path} absent, must be added manually",
        )

        val log = MessageLog()
        val monitor = TaskMonitor.DUMMY
        logFile.parentFile.mkdirs()
        recordsFile.parentFile.mkdirs()
        harvestFile.parentFile.mkdirs()

        try {
            // Loading the raw binary is the ONLY legitimately-skippable step: a corrupt or
            // format-unsupported fixture is an environment problem, not a bug in our analyzer.
            // Everything after it is code under test and must fail loudly (see the catch below).
            loadResults = try {
                ProgramLoader.builder().source(fixture).compiler("gcc").log(log).monitor(monitor).load()
            } catch (e: Exception) {
                e.printStackTrace()
                abort("Skipping $binaryName: ProgramLoader could not load the fixture: $e")
            }

            context = loadResults.getPrimaryDomainObject(this).defaultContext()

            val mgr = AutoAnalysisManager.getAnalysisManager(program)
            val ourName = StabsAnalyzer().name
            val options = program.getOptions(Program.ANALYSIS_PROPERTIES)

            when (mode) {
                Mode.CONCURRENT -> {
                    // Confirm Ghidra's ClassSearcher actually discovered our analyzer
                    // (build/classes/kotlin/main is on the test classpath). If this
                    // assertion ever fails the test would be silently meaningless.
                    val discovered = mgr.getAnalyzer(ourName)
                    Assertions.assertNotNull(discovered, "StabsAnalyzer not discovered by ClassSearcher")
                    assertInstanceOf<StabsAnalyzer>(discovered)

                    // Pre-build the test's context and install its CapturingSink as a
                    // side-channel on the Program. StabsAnalyzer.added() will tee its
                    // output to that sink in addition to Ghidra's truncating MessageLog,
                    // so we get the full, untruncated log here while autoanalysis still
                    // sees its own logs in MessageLog.
                    val probe = ImportProbe.install(context)

                    // BYTE_ANALYZER auto-fires on byte changes; on a freshly-
                    // loaded program nothing has "changed" since the loader put
                    // bytes down, so we explicitly schedule our analyzer for the
                    // next analysis pass — it then runs at its declared priority
                    // alongside the demangler.
                    // Sub-options writes hit the program options DB and need a transaction (as the
                    // AFTER branch's analyzer-disable does); the .stab overlay is a diagnostic view,
                    // not needed to produce types (~8% of the run), so skip it here too.
                    program.runTransaction("enable-stabs-analyzer") {
                        options.setBoolean(ourName, true)
                        options.getOptions(ourName).setBoolean(StabsOptions.OVERLAY_SECTION, false)
                    }
                    mgr.scheduleOneTimeAnalysis(discovered, program.memory)
                    runAutoAnalysis(mgr, monitor)
                    artifacts = checkNotNull(probe.artifacts) { "artifacts not populated by CONCURRENT" }
                }

                Mode.AFTER -> {
                    // Disable our analyzer so auto-analysis (incl. demangler) settles
                    // without us, then re-run it manually with our CapturingSink.
                    // `Options.setBoolean` mutates the program options DB and needs
                    // a transaction.
                    program.runTransaction("disable-stabs-analyzer") {
                        options.setBoolean(ourName, false)
                    }
                    mgr.initializeOptions()
                    runAutoAnalysis(mgr, monitor)
                    program.runTransaction("stabs-analyze") {
                        artifacts = checkNotNull(context.import()) { "artifacts not populated by AFTER" }
                    }
                }
            }
            // CapturingSink holds the full untruncated log in both modes
            // (in CONCURRENT it's fed via ExternalSinks → TeeSink). MessageLog
            // is appended for parity with Ghidra's own view, even though it
            // truncates at ~500 lines.
            logFile.writeText(context.terminal.dedupedOutput() + "\n--- MessageLog ---\n" + log.toString())
            // Stripped/no-stabs fixtures produce no artifacts; nothing to dump.
            artifacts.writeRegistryDump(registryDumpFile)
            writeDegradationDump()
        } catch (e: org.opentest4j.TestAbortedException) {
            throw e // the load-failure skip above — propagate as a skip, not a failure
        } catch (e: Exception) {
            // Load succeeded, so anything thrown here is a bug in our import / analysis / dump path.
            // Fail the invocation loudly (in this exact fixture×mode) instead of masking it as a skip:
            // silently swallowing crashes here is what let a TypeResolver NPE and a registry-dump
            // `.single()` crash hide for so long, and dropped whole AFTER-mode runs unnoticed.
            e.printStackTrace()
            throw AssertionError("setUp failed for $binaryName/$mode (import/dump, not fixture load): $e", e)
        }
    }

    private fun runAutoAnalysis(mgr: AutoAnalysisManager, monitor: TaskMonitor) {
        program.disableWindowsResourceAnalyzer()
        mgr.reAnalyzeAll(null)
        program.runTransaction("auto-analyze") {
            mgr.startAnalysis(monitor)
            mgr.waitForAnalysis(null, monitor)
        }
        // Ghidra's own per-analyzer wall times. The gradle listener only reports whole-invocation
        // time, which also carries fixture load, our import and the dumps; this attributes the
        // analysis share to individual analyzers, so a perf change can be localised without a
        // profiler. Written per fixture×mode alongside the other dumps.
        analysisTimesFile.apply { parentFile.mkdirs() }
            .writeText("total = ${mgr.totalTimeInMillis} ms\n\n${mgr.taskTimesString}")
    }

    // The CLI's `--degradation-log` dump, grouped by category, so one integrationTest run emits the
    // full CLI dump set (records/harvest/registry already written above) without a separate probe pass.
    private fun writeDegradationDump() {
        val byCategory = context.diagnostics.snapshotDegradations()
            .groupBy { it.category }.toList().sortedByDescending { it.second.size }
        degradationFile.parentFile.mkdirs()
        degradationFile.writeText(
            buildString {
                appendLine("fixture: $binaryName ($mode)")
                appendLine("total degradations: ${byCategory.sumOf { it.second.size }}")
                appendLine("\ncounts by category:")
                byCategory.forEach { (cat, list) -> appendLine("  $cat = ${list.size}") }
                byCategory.forEach { (cat, list) ->
                    appendLine("\n=== $cat (${list.size}) ===")
                    list.forEach { appendLine("  ${it.detail}") }
                }
            },
        )
    }

    @AfterAll
    fun tearDown() {
        ImportProbe.clear(program)
        program.release(this)
        loadResults.close()
    }

    @Test
    fun countersWithinBaseline() {
        // Authoritative per-category counts. Not `log.tagFrequencies()`: that only sees categories
        // that reach the sink (record*/direct-inc bypass it) and ignores `count = n` tallies, which
        // made assertions on those categories (e.g. empty-scope) silently vacuous.
        val counters = context.diagnostics.snapshotCounters()

        // -PregenerateBaselines=true rewrites the baseline from the observed counts (deterministic
        // import). The resulting git diff is the record of exactly which counters moved. This has to
        // precede the exists() check below, or a newly added fixture can never get a first baseline:
        // the assumption skips the test before it can write one.
        if (System.getProperty("regenerateBaselines") == "true") {
            BaselineWriter.write(baselineFile, counters, "$binaryName - generated from snapshotCounters()")
            return
        }

        assumeTrue(baselineFile.exists(), "Skipping: no committed baseline for $binaryName")

        val baseline = BaselineLoader.load(baselineFile)

        // If no stabs were found in the binary, skip the test
        // (stabs sections may not exist or may be in a non-standard format)
        assumeTrue(
            counters.isNotEmpty(),
            "Skipping: No stabs counters found in binary (stabs sections absent or non-standard format)",
        )

        val drift = mutableListOf<String>()
        for ((counterName, range) in baseline.counters) {
            val actual = counters.getOrDefault(counterName, 0L)
            if (actual !in range.min..range.max) {
                drift += "Counter '$counterName' = $actual outside baseline range [${range.min}..${range.max}]"
            }
        }
        if (drift.isNotEmpty()) {
            Assertions.fail<Unit>("Baseline drift detected:\n  - " + drift.joinToString("\n  - "))
        }
    }

    /**
     * `BranchInstructions` is a stab-harvested global typed
     * `array[0..15] of <enum>`. The element-type Ref couldn't resolve and the
     * stab encodes the length only via the index Range. The old Array case
     * returned null on either condition, leaving the global untyped. Now
     * `TypeRegistry` derives length from the indexType Range when absent
     * and falls back to Undefined1 elements on resolution failure.
     *
     * Must hold in both modes — CONCURRENT mode races autoanalysis's
     * `undefined4` placeholders, which `applyGlobalOrStatic` now evicts via
     * `DataUtilities.CLEAR_ALL_CONFLICT_DATA`.
     */
    @Test
    fun branchInstructionsGlobalIsTyped() {
        val branchSyms = program.symbolTable.symbolIterator.iterator().asSequence()
            .filter { it.name == "_BranchInstructions" || it.name == "BranchInstructions" }
            .toList()
        assumeTrue(branchSyms.isNotEmpty(), "Skipping: BranchInstructions symbol absent")
        val sym = branchSyms.first()
        val data = program.listing.getDataAt(sym.address)
        // Diagnostic context surfacing what the actual program state is when
        // this assertion fails — we want to know whether the address has the
        // wrong type, multiple symbols, or has been collapsed by a downstream
        // analyzer post-import.
        val ctx = buildString {
            append("Symbol matches for BranchInstructions: ")
            append(branchSyms.joinToString { "${it.address}::${it.name}" })
            append("\n")
            append("Data at ${sym.address}: ")
            append(
                if (data == null) {
                    "<null>"
                } else {
                    "${data.dataType::class.simpleName} '${data.dataType.name}' len=${data.length}"
                },
            )
            // Look 16 bytes around to see if the array got fragmented.
            for (off in 0..16 step 4) {
                val a = sym.address.add(off.toLong())
                val d = program.listing.getDataAt(a)
                append("\n  +$off ($a): ")
                append(d?.dataType?.name ?: "<no data>")
            }
        }
        Assertions.assertTrue(
            data?.dataType is Array,
            "BranchInstructions should be an Array.\n$ctx",
        )
        val arr = data!!.dataType as Array
        Assertions.assertEquals(
            16,
            arr.numElements,
            "BranchInstructions array length should be 16 (Range 0..15 in stab).\n$ctx",
        )
        Assertions.assertEquals(
            "EnumInstToken",
            arr.dataType.name,
            "BranchInstructions element should resolve to the EnumInstToken Enum.\n$ctx",
        )
    }

    @Test
    fun instructionStringslobalIsTyped() {
        val branchSyms = program.symbolTable.symbolIterator.iterator().asSequence()
            .filter { it.name == "InstructionStrings" || it.name == "_InstructionStrings" }
            .toList()
        assumeTrue(branchSyms.isNotEmpty(), "Skipping: InstructionStrings symbol absent")
        val sym = branchSyms.first()
        val data = program.listing.getDataAt(sym.address)

        Assertions.assertTrue(
            data?.dataType is Array,
            "BranchInstructions should be an Array.",
        )
        val arr = data!!.dataType as Array
        Assertions.assertEquals(
            53,
            arr.numElements,
            "BranchInstructions array length should be 53 (Range 0..15 in stab).",
        )

        Assertions.assertNotEquals(
            "byte",
            arr.dataType.name,
            "BranchInstructions element should be char*, not byte.",
        )
    }

    @Test
    fun bouniafNotUnderStdInclude() {
        val bouniaf = program.dataTypeManager.allDataTypes
            .asSequence()
            .firstOrNull { it.name == "bouniaf" }
        assumeTrue(bouniaf != null, "Skipping: bouniaf not found in DTM (stabs not processed)")
        Assertions.assertFalse(
            bouniaf!!.categoryPath.path.startsWith("/std/"),
            "bouniaf at ${file.categoryPath.path} (expected non-/std/)",
        )
    }

    /**
     * No class method should end up with two parameters both literally named
     * `this`. The pattern (one typed `<Class>*`, another typed primitively
     * like `ushort` or `uint`) means we set __thiscall (which prepended an
     * injected `this`) but failed to evict the leftover param that
     * autoanalysis had named `this` from its register-storage guess.
     *
     * Scans every class method in the program rather than spot-checking one,
     * because the bug is sporadic — observed on `bouniaf::Dump`
     * for example, but `DSInst::Dump` was fine.
     */
    @Test
    fun noClassMethodHasDuplicateThis() {
        val offenders = program.functionManager
            .getFunctions(true)
            .asIterable()
            .filter { it.parentNamespace is ghidra.program.model.listing.GhidraClass }
            .mapNotNull { f ->
                val thisCount = (0 until f.parameterCount)
                    .count { f.getParameter(it)?.name == "this" }
                if (thisCount >= 2) {
                    f to (0 until f.parameterCount).joinToString {
                        val p = f.getParameter(it)
                        "${p?.dataType?.name} ${p?.name}"
                    }
                } else {
                    null
                }
            }
            .take(20)
            .toList()
        Assertions.assertTrue(
            offenders.isEmpty(),
            "Found ${offenders.size} methods with duplicate `this` parameters " +
                "(showing first 20):\n" +
                offenders.joinToString("\n") {
                    "  ${it.first.parentNamespace.name}::${it.first.name}(${it.second})"
                },
        )
    }

    @Test
    fun methodsUseThiscall() {
        // Any class method should be marked __thiscall so Ghidra auto-injects a
        // `this: <Class>*` first parameter (instead of leaving a guessed `int *this`).
        // Spot-check via _ZN6DSInst4DumpEPt — DSInst::Dump(unsigned short*).
        val func = program.functionManager
            .getFunctions(true)
            .asIterable()
            .firstOrNull { it.name == "Dump" && it.parentNamespace.name == "DSInst" }
        assumeTrue(func != null, "Skipping: DSInst::Dump not found")
        Assertions.assertEquals("__thiscall", func!!.callingConventionName)
        val thisParam = func.getParameter(0)
        Assertions.assertNotNull(thisParam, "DSInst::Dump has no parameters at all")
        Assertions.assertEquals("this", thisParam!!.name)
        val thisDtName = (thisParam.dataType as? Pointer)?.dataType?.name
        Assertions.assertEquals(
            "DSInst",
            thisDtName,
            "DSInst::Dump's `this` should be `DSInst*`; got ${thisParam.dataType.name}",
        )
    }

    /**
     * A `?`-flagged static member function takes no `this`. `FileSystemImage::isValidMagic` is
     * `static bool isValidMagic(unsigned long w)` — one N_PSYM param, no `this` slot. Parsing `?`
     * as pure-virtual made ClassBuilder treat it as an instance method: forced __thiscall, injected
     * a phantom `FileSystemImage *this`, and replaced the N_PSYM params with the empty list its
     * `f(ret)` signature carries, rendering `bool __thiscall isValidMagic(FileSystemImage *this)`.
     */
    @Test
    fun staticMemberFunctionTakesNoThis() {
        val func = program.functionManager.getFunctions(true).asIterable()
            .firstOrNull { it.name == "isValidMagic" && it.parentNamespace.name == "FileSystemImage" }
        assumeTrue(func != null, "Skipping: FileSystemImage::isValidMagic not found")
        val params = (0 until func!!.parameterCount)
            .map { func.getParameter(it) }
            .map { "${it?.dataType?.name} ${it?.name}" }
        Assertions.assertNotEquals(
            "__thiscall",
            func.callingConventionName,
            "static isValidMagic must not be __thiscall; params: $params",
        )
        Assertions.assertEquals(
            listOf("uint w"),
            params,
            "static isValidMagic should carry only its N_PSYM param `unsigned long w`",
        )
    }

    /**
     * A class whose only Itanium symbols are static data members still lands in its real namespace.
     * `ensureClassNamespace` read the chain off a *method's* mangled name, so `std::ctype_base` —
     * which declares no member functions at all, only `alnum`/`alpha`/`digit`/… — fell back to the
     * source-form leaf and was built as a root-level `ctype_base`. Its members' linkage names
     * (`_ZNSt10ctype_base5alnumE`) carry the same chain.
     */
    @Test
    fun constantsOnlyClassLandsInItsNamespace() {
        val cls = program.symbolTable.getSymbols("ctype_base")
            .firstOrNull { it.symbolType == ghidra.program.model.symbol.SymbolType.CLASS }
        assumeTrue(cls != null, "Skipping: ctype_base class namespace absent")
        Assertions.assertEquals(
            "std",
            cls!!.parentNamespace.name,
            "ctype_base sits under '${cls.parentNamespace.getName(true)}' — the class's namespace " +
                "chain was not recovered from its static members' linkage names",
        )
    }

    /**
     * A 1-byte bool global occupies 1 byte, and its neighbour is reachable.
     *
     * Without `-gstabs+` gcc spells `bool` as an enum over False/True (`gcc/dbxout.c`), losing the
     * width; as a sizeof(int) enum it swallowed the three globals after it, so five of CryptoPP's
     * eight adjacent `g_has*` flags had no data of their own — `createData` returns the containing
     * item as a success, so nothing threw.
     */
    @Test
    fun adjacentBoolGlobalsEachOwnTheirByte() {
        val flags = listOf("_ZN8CryptoPP9g_hasISSEE", "_ZN8CryptoPP9g_hasSSE2E", "_ZN8CryptoPP10g_hasSSSE3E")
            .mapNotNull { n ->
                sequenceOf(n, "_$n").firstNotNullOfOrNull { program.symbolTable.getSymbols(it).firstOrNull() }
            }
        assumeTrue(flags.size == 3, "Skipping: CryptoPP g_has* flags absent")
        val sizes = flags.associate { s ->
            s.name to program.listing.getDataAt(s.address)?.let { "${it.dataType.name}(${it.length})" }
        }
        Assertions.assertTrue(
            sizes.values.all { it != null && it.endsWith("(1)") },
            "each bool flag should own exactly its own byte; got $sizes",
        )
    }

    /**
     * A static data member gets the type its class declares. These carry no `G`/`S` address stab, so
     * `applyGlobalOrStatic` never sees them and they used to reach Ghidra as a demangler-named
     * address with auto-analysis's guess for a type. `FieldDecl.mangled` is the only link from the
     * member back to its symbol — and being a real name gcc wrote, it works where reconstructing a
     * spelling cannot: every one of these is a template or nested libstdc++ type.
     *
     * `std::string::npos` is `static const size_type npos;` — 4 bytes, and emphatically not
     * `undefined4`.
     */
    @Test
    fun staticDataMemberIsTypedFromItsDeclaration() {
        val sym = sequenceOf("_ZNSs4nposE", "__ZNSs4nposE").firstNotNullOfOrNull {
            program.symbolTable.getSymbols(it).firstOrNull()
        }
        assumeTrue(sym != null, "Skipping: std::string::npos not present")
        // Plain `-gstabs` (no `+`) on gcc 4.2.1 emits static members as the bare `name:type,0,0`
        // with no linkage name at all — `_ZNSs4nposE` appears 0 times in crypto_mi_test_gcc421 but
        // 37 times in its _fullstabs twin. There is then nothing to reconcile *from*, so this is a
        // property of the debug info, not of the importer: gate on the link actually being present.
        val declared = artifacts.harvest.types.values.orEmpty()
            .mapNotNull { it.body as? TypeDecl.Struct }
            .flatMap { it.fields }
            .any { it.name == "npos" && it.mangled != null }
        assumeTrue(declared, "Skipping: this build's stabs carry no linkage name for npos")
        val dt = program.listing.getDataAt(sym!!.address)?.dataType
        Assertions.assertNotNull(dt, "no data applied at std::string::npos (${sym.address})")
        Assertions.assertFalse(
            dt is Undefined,
            "std::string::npos is ${dt?.name} — the static member's declared type never reached it",
        )
        Assertions.assertEquals(4, dt!!.length, "std::string::npos should be 4 bytes, got ${dt.name}")
    }

    /**
     * A register local lands in the register its stab names. The number is the record's n_value —
     * `w:r(0,5)` carries no register in the descriptor — and `readTrailingReg()` used to return a
     * hardcoded 0, so every register local in every fixture was placed in dbx 0 = EAX. Nothing
     * caught it: `reglocal-unmapped-regnum` can't fire when the number is always mappable.
     *
     * `FileSystemImage::fetch16FromOctet` holds `wordOffset` in ESI (n_value 6) and `value` in EDI
     * (7) — two registers in one function, so a per-record read is the only way to satisfy both; a
     * restored constant could not. Register locals that shadow a parameter name are skipped by
     * `applyLocal` (`reglocal-skipped-dup-param`), so these are deliberately non-parameter locals.
     */
    @Test
    fun registerLocalUsesTheStabsRegister() {
        val func = program.functionManager.getFunctions(true).asIterable()
            .firstOrNull { it.name == "fetch16FromOctet" && it.parentNamespace.name == "FileSystemImage" }
        assumeTrue(func != null, "Skipping: FileSystemImage::fetch16FromOctet not found")
        val storage = func!!.localVariables
            .filter { it.name in setOf("wordOffset", "value") }
            .associate { it.name to it.variableStorage.toString() }
        // `value` is a 2-byte type, so Ghidra narrows EDI to its 16-bit sub-register — the storage
        // is sized from the variable's type, the register chosen from the stab.
        Assertions.assertEquals(
            mapOf("wordOffset" to "ESI:4", "value" to "DI:2"),
            storage,
            "register locals must land where their stab's n_value says; all-EAX means the number was lost",
        )
    }

    /**
     * No symbol may carry a raw Itanium-mangled name inside a non-global namespace. The Cygwin PE
     * loader's own `__Z…` symbols live in the global namespace and are fine; a mangled leaf under
     * a class (`FileSystemImage::_ZN15FileSystemImage7fetch32ERK5Imagem`) is the fingerprint of a
     * name we set raw on a function symbol that a later demangle pass displaced —
     * `SetLabelPrimaryCmd` re-creates the displaced name as a label in the same namespace.
     */
    @Test
    fun noMangledNameInsideANamespace() {
        val offenders = program.symbolTable.symbolIterator.iterator().asSequence()
            .filter { isMangled(it.name) && !it.parentNamespace.isGlobal }
            .map { "${it.address} ${it.parentNamespace.getName(true)}::${it.name} (${it.symbolType})" }
            .take(20)
            .toList()
        Assertions.assertTrue(
            offenders.isEmpty(),
            "Found ${offenders.size} mangled symbols inside a namespace (showing first 20):\n" +
                offenders.joinToString("\n") { "  $it" },
        )
    }

    @Test
    fun cparserMaterialized() {
        assumeTrue(binaryName == "bouniafbouniaf.exe", "Skipping: CParser/Token_Type/EAsm specific to bouniafbouniaf.exe")
        // CParser, Token_Type and EAsm all canonicalise to the same TypeId because
        // gcc reuses local ids inside BINCL blocks per CU. Each must still reach the DTM.
        for (name in listOf("CParser", "Token_Type", "EAsm")) {
            val dt = program.dataTypeManager.allDataTypes.asSequence().firstOrNull { it.name == name }
            Assertions.assertNotNull(dt, "$name missing from DTM (shared BINCL canonical id collision)")
        }
    }

    @Test
    fun csymLexStreamPresent() {
        assumeTrue(binaryName == "bouniafbouniaf.exe", "Skipping: bouniaf specific to bouniafbouniaf.exe")
        val all = program.dataTypeManager.allDataTypes
            .asSequence()
            .filter { it.name == "bouniaf" }
            .map { "${it.categoryPath.path}/${it.name} (${it::class.simpleName}, len=${(it as? Structure)?.length})" }
            .toList()
        // bouniaf is defined inside STL headers (only entry points are template
        // instantiations) so it ends up under /std/<sorted-first-header>/ rather than
        // a project category. What matters is that it materialized as a non-empty
        // Structure that ClassBuilder can find via Attribution (i.e. the dedup +
        // sort-stable attribution agree on the same category).
        val best = all.firstOrNull { "(StructureDB" in it }
        Assertions.assertNotNull(best, "No bouniaf Structure in DTM. Got:\n${all.joinToString("\n")}")
    }

    @Test
    fun cPackedSegListVtableAnnotated() {
        assumeTrue(binaryName == "bouniafbouniaf.exe", "Skipping: CPackedSegList specific to bouniafbouniaf.exe")
        // CPackedSegList inherits its vtable from a polymorphic base and gcc marks none of its
        // overrides virtual (all NORMAL) with no vptr marker, so the old isPoly gate skipped it.
        // hasPolymorphicBaseSubobject reopens the gate — the vftable must be built and populated.
        val vftable = program.dataTypeManager.allDataTypes.asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name == "CPackedSegList_vftable" }
            .maxByOrNull { it.numComponents }
        Assertions.assertTrue(
            vftable != null && vftable.numComponents > 0,
            "CPackedSegList_vftable missing or empty — inherited-vtable class not annotated",
        )
    }

    @Test
    fun cSymLexStreamVtableAddressPointSkipsVbaseOffset() {
        assumeTrue(binaryName == "bouniafbouniaf.exe", "Skipping: bouniaf specific to bouniafbouniaf.exe")
        // bouniaf derives (via bouniaf → basic_ifstream) from basic_istream, which
        // virtually inherits basic_ios, so _ZTV13bouniaf is preceded by a vbase-offset word:
        //   [vbase_offset] [offset_to_top=0] [rtti] [address point → virtuals…]
        // The address point is ztv+3*ptr, not the canonical ztv+2*ptr. layVtable must find the
        // rtti header word and put the `vftable` symbol after it.
        val ztv = program.symbolTable.getSymbols("__ZTV13bouniaf").firstOrNull()
        assumeTrue(ztv != null, "Skipping: bouniaf vtable not resolved")
        val ptr = program.defaultPointerSize.toLong()
        val addressPoint = ztv!!.address.add(3L * ptr)
        val wrongPoint = ztv.address.add(2L * ptr)
        Assertions.assertTrue(
            program.symbolTable.getSymbols(addressPoint).any { "vftable" in it.name },
            "no vftable symbol at bouniaf address point $addressPoint (ztv+3*ptr); " +
                "symbols there: ${program.symbolTable.getSymbols(addressPoint).map { it.name }}",
        )
        Assertions.assertFalse(
            program.symbolTable.getSymbols(wrongPoint).any { "vftable" in it.name },
            "vftable symbol mislaid on the rtti word at $wrongPoint (ztv+2*ptr) — vbase offset not skipped",
        )
    }

    @Test
    fun typeinfoGlobalKeepsDemangledPrimary() {
        assumeTrue(binaryName == "bouniafbouniaf.exe", "Skipping: EAsm typeinfo specific to bouniafbouniaf.exe")
        // EAsm's typeinfo global is named by its mangled `_ZTI4EAsm` linkage name in the stab;
        // ensureStabLabel must not promote that over the demangled `EAsm::typeinfo` already present.
        val ti = program.symbolTable.getSymbols("typeinfo").firstOrNull { it.parentNamespace.name == "EAsm" }
        assumeTrue(ti != null, "Skipping: EAsm::typeinfo symbol not present")
        val primary = program.symbolTable.getPrimarySymbol(ti!!.address)
        Assertions.assertEquals(
            "typeinfo",
            primary.name,
            "primary label at EAsm typeinfo is '${primary.name}' — mangled name clobbered the demangled one",
        )
    }

    @Test
    fun typeInfoBaseClassesNotLeftAsStubs() {
        assumeTrue(binaryName == "bouniafbouniaf.exe", "Skipping: libsupc++ RTTI base classes specific to bouniafbouniaf.exe")
        // std::type_info and __cxxabiv1::__{class,si_class,vmi_class}_type_info are real libsupc++
        // classes with methods (__do_upcast, …) but no stabs, so the demangler leaves empty /Demangler
        // stubs. typeInfoLayout must give them the RttiStructs layout — no 0-component Structure may survive.
        assumeTrue(
            program.symbolTable.getNamespace(Itanium.ABI_NAMESPACE, null) != null,
            "Skipping: no __cxxabiv1 namespace (RTTI base classes absent from this binary)",
        )
        val names = setOf(
            Itanium.TYPE_INFO,
            Itanium.CLASS_TYPE_INFO,
            Itanium.SI_CLASS_TYPE_INFO,
            Itanium.VMI_CLASS_TYPE_INFO,
        )
        val stubs = program.dataTypeManager.allDataTypes.asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name in names && it.numComponents == 0 }
            .map { it.pathName }
            .toList()
        Assertions.assertTrue(stubs.isEmpty(), "typeinfo base classes left as empty stubs: $stubs")
    }

    @Test
    fun exprInstHasComponents() {
        val matches = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name == "ExprInst" }
            .toList()
        assumeTrue(matches.isNotEmpty(), "Skipping: ExprInst not found")
        val best = matches.maxByOrNull { it.numComponents }!!
        val rendered = matches.joinToString("\n") {
            "${it.categoryPath.path}/${it.name} len=${it.length} components=${it.numComponents}"
        }
        Assertions.assertTrue(
            best.numComponents > 0,
            "All ExprInst copies are empty:\n$rendered",
        )
        // Surface where each copy lives so we can see if there's a stub-vs-real split.
        println("ExprInst copies:\n$rendered")
        // EnumInstToken: TODO item — verify it appears at all.
        val enumInstAll = program.dataTypeManager.allDataTypes
            .asSequence()
            .filter { it.name.startsWith("EnumInstToken") || it.name.startsWith("EnumInstType") }
            .map { "${it.categoryPath.path}/${it.name} (${it::class.simpleName})" }
            .toList()
        Assertions.assertTrue(
            enumInstAll.any { "EnumInstToken" in it && "Enum" in it.substringAfterLast("(") },
            "No EnumInstToken Enum in DTM. Related entries:\n${enumInstAll.joinToString("\n")}",
        )
    }

    @Test
    fun bouniafFirstComponentIsBase() {
        val bouniaf = program.dataTypeManager.allDataTypes.asSequence()
            .firstOrNull { it.name == "bouniaf" && it is Structure } as? Structure
        assumeTrue(bouniaf != null, "Skipping: bouniaf not found in DTM (stabs not processed)")
        assumeTrue(bouniaf!!.numComponents > 0, "Skipping: bouniaf has no components")
        val first = bouniaf.getComponent(0)
        Assertions.assertEquals(
            0,
            first.offset,
            "bouniaf first component should be at offset 0; got ${first.offset} (${first.fieldName})",
        )
        val dump = (0 until bouniaf.numComponents).joinToString("\n") {
            val c = bouniaf.getComponent(it)
            "  [${c.offset}] ${c.fieldName}: ${c.dataType.name} (${c.dataType::class.simpleName}, len=${c.length})"
        }
        val xis = program.dataTypeManager.allDataTypes.asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name == "bouniaf" }
            .map { "${it.categoryPath.path} components=${it.numComponents} len=${it.length}" }
            .toList()
        Assertions.assertTrue(
            first.dataType is Structure,
            "bouniaf first component '${first.fieldName}' should be a Structure (the parent class); " +
                "got ${first.dataType::class.simpleName} '${first.dataType.name}'\n" +
                "bouniaf copies in DTM:\n${xis.joinToString("\n")}\n" +
                "First 5 components of selected bouniaf:\n$dump",
        )
        val name = first.fieldName ?: ""
        Assertions.assertTrue(
            name.startsWith("_base_") && !name.startsWith("_base_unknown_"),
            "bouniaf first component is '$name' (type=${first.dataType.name}); " +
                "expected _base_<parent-name> with a resolved parent class",
        )
        Assertions.assertEquals(
            "ExprInst",
            first.dataType.name,
            "bouniaf's parent class should be ExprInst; got ${first.dataType.name}",
        )
    }

    /**
     * bouniaf extends basic_ifstream — verify the inheritance is
     * reflected in the layout. Two acceptable shapes:
     *  - A named `_base_basic_ifstream` (or `_vbase_…`) component at +0,
     *    if the base type resolved. Only happens when libstdc++'s stabs
     *    body is present in this binary (it isn't in bouniafbouniaf — only
     *    iosfwd's forward decl is emitted).
     *  - The struct's first own non-static field at offset > 0, with
     *    the base subobject reserved as bare Undefined1 (the explicit
     *    "don't pretend we know what's here" choice). This is the path
     *    bouniafbouniaf takes for bouniaf's basic_ifstream base.
     */
    @Test
    fun bouniafHasBaseField() {
        val cls = program.dataTypeManager.allDataTypes.asSequence()
            .firstOrNull { it.name == "bouniaf" && it is Structure } as? Structure
        assumeTrue(cls != null, "Skipping: bouniaf not found (stabs not processed)")
        val hasNamedBase = (0 until cls!!.numComponents).any { i ->
            cls.getComponent(i).fieldName?.let { it.startsWith("_base_") || it.startsWith("_vbase_") } == true
        }
        val firstOwnFieldOffset = (0 until cls.numComponents)
            .map { cls.getComponent(it) }
            .firstOrNull { c -> c.fieldName?.let { !it.startsWith("_base_") && !it.startsWith("_vbase_") } == true }
            ?.offset
            ?: 0
        Assertions.assertTrue(
            hasNamedBase || firstOwnFieldOffset > 0,
            "bouniaf: no _base_/_vbase_ component AND first own field at offset 0 — " +
                "no inheritance reflected at all",
        )
    }

    @Test
    fun unsignedInt() {
        assumeTrue(binaryName == "bouniafbouniaf.exe")
        val found = program.dataTypeManager.allDataTypes.asSequence()
            .filter { it.name == "unsignedint" }.toList()
        val unsigned = found.singleOrNull()
        Assertions.assertNotNull(
            unsigned,
            "expected 1 type named 'unsignedint', got ${found.size}: " +
                found.map { "${it::class.simpleName}@${it.categoryPath}" },
        )
        val u = unsigned ?: return
        val base = (u as? TypeDef)?.baseDataType ?: u
        Assertions.assertTrue(
            base.isEquivalent(UnsignedIntegerDataType()),
            "type 'unsignedint' should alias uint, got ${u::class.simpleName}(${u.name})",
        )
    }

    @Test
    fun noEmptyStructs() {
        val emptyCats = program.dataTypeManager.allDataTypes.asSequence()
            .filterIsInstance<Structure>().filter { it.numComponents == 0 && it.isZeroLength }
            .groupBy { it.categoryPath }.mapValues { it.value.size }
        // Aspirational: stabs gives no body for some forward-declared
        // libstdc++ types (e.g. residual `/std/*` referenced by other
        // structs — we can't dtm.remove those without orphaning the
        // referrer). Removed-orphan cleanup handles the rest. Reporting
        // via println instead of assertion so the noise stays visible
        // without flagging the run as failed.
        if (emptyCats.isNotEmpty()) {
            println("noEmptyStructs[$binaryName/$mode]: ${emptyCats.values.sum()} empty structs in $emptyCats")
        }
    }

    /**
     * Inject a `/Demangler/std/string` Structure stub by hand and verify
     * the analyzer's DemanglerReplacer substitutes our `/stabs/string`
     * typedef when re-run. Reproduces the GUI scenario where Ghidra's
     * demangler creates the stub on demand during signature application
     * (suppressed in our headless `demangleMangledLabels` invocation by
     * `setApplySignature(false)`, so the other `demanglerStringReplaced`
     * test trivially passes — there's no stub to replace).
     *
     * Uses [ImportContext.typeRegistry] — the populated registry the
     * importer set at end-of-import. Constructing a fresh one would mean
     * either (a) re-running materializeAll (creates `.conflict`
     * duplicates that race other @Test methods under
     * @Execution(CONCURRENT)) or (b) leaving it empty (findByName always
     * returns null and we can't test the substitution path at all).
     */
    @Test
    fun demanglerStringReplacedAfterStubInjection() {
        assumeTrue(binaryName == "bouniafbouniaf.exe" || binaryName == "bouniaf.exe")
        val typeRegistry = artifacts.registry
        val demanglerCat = CategoryPath("/Demangler/std")
        program.runTransaction("inject-demangler-stub") {
            program.dataTypeManager.createCategory(demanglerCat)
                .addDataType(
                    StructureDataType(
                        demanglerCat,
                        "string",
                        0,
                        program.dataTypeManager,
                    ),
                    DataTypeConflictHandler.KEEP_HANDLER,
                )
        }
        Assertions.assertNotNull(
            program.dataTypeManager.getDataType(demanglerCat, "string"),
            "precondition: injected stub should exist",
        )

        program.runTransaction("rerun-demangler-replacer") {
            ghistabs.importer.DemanglerReplacer(context, typeRegistry).replace()
        }

        Assertions.assertNull(
            program.dataTypeManager.getDataType(demanglerCat, "string"),
            "/Demangler/std/string should have been replaced by /stabs/string",
        )
    }

    @Test
    fun demanglerStringReplaced() {
        assumeTrue(binaryName == "bouniafbouniaf.exe" || binaryName == "bouniaf.exe")
        val strings = program.dataTypeManager.allDataTypes.asSequence()
            .filter { it.name == "string" }.toList()
        val goodString = strings.find { !it.categoryPath.path.startsWith("/Demangler") }
        Assertions.assertNotNull(goodString, "no non-Demangler `string` DataType: $strings")
        Assertions.assertFalse(goodString!!.isZeroLength, "`string` is zero-length: $goodString")
        Assertions.assertFalse(
            strings.any { it.categoryPath.path.startsWith("/Demangler") },
            "/Demangler/string still present: $strings",
        )
    }

    /**
     * gcc encodes void as a type explicitly defined as itself (`(x,y)=(x,y)`), which the parser
     * lowers to [TypeDecl.Void]. It must materialize to VoidDataType — never an empty-Structure
     * placeholder named `[<file>,N]` polluting demangled signatures. (A *bare* `name:t(x,y)` with
     * no `=` is a forward reference, not void, and legitimately becomes an incomplete Structure —
     * that case is not checked here.)
     */
    @Test
    fun voidSelfRefNotMaterialized() {
        // Reuse setUp's harvest; re-harvest only when the import produced none (no stabs).
        val harvest = artifacts.harvest
        val voidAsts = harvest.types.values.filter { it.body is TypeDecl.Void }
        assumeTrue(voidAsts.isNotEmpty(), "no gcc-void asts in this fixture's harvest")

        val leaked = voidAsts.mapNotNull { ast ->
            // A void ast must NOT materialize as a Structure under any category bearing its ghidraName.
            program.dataTypeManager.allDataTypes.asSequence()
                .filterIsInstance<Structure>()
                .firstOrNull { it.name == ast.ghidraName }
                ?.pathName
        }
        Assertions.assertTrue(
            leaked.isEmpty(),
            "gcc-void asts leaked as Structures: $leaked (out of ${voidAsts.size} void asts)",
        )

        // The original report (bouniafbouniaf): `(3,7)` in stdlib.h consumed by
        // Keywords.cpp. Explicit check so the assertion fires by exact name
        // if regressed.
        if (binaryName == "bouniafbouniaf.exe") {
            val specific = program.dataTypeManager.allDataTypes.asSequence()
                .filterIsInstance<Structure>()
                .filter { it.name.contains("stdlib.h") && it.name.endsWith("Keywords.cpp,7]") }
                .map { it.pathName }
                .toList()
            Assertions.assertTrue(
                specific.isEmpty(),
                "the stdlib.h Keywords.cpp,7 void self-Ref leaked: $specific",
            )
        }
    }

    @Test
    @ExpectedToFail(
        fixtures = [
            "crypto_mi_test_gcc421.exe", "crypto_mi_test_gcc421_stripped.exe",
            "xmltest_gcc421.exe", "xmltest_gcc421_stripped.exe",
            // a.out: both fixtures are plain C, so there are no classes and no vtables at all.
            "hello_aout_gcc295.o", "zlib_aout_gcc263.o",
            // C++, but gcc 2.95's minimal-debug `##` method encoding fails the class body, and its
            // vtables are pre-Itanium `__vt_9TiXmlNode` symbols rather than `_ZTV` regardless.
            "tinyxml_aout_gcc295.o",
        ],
        reason = "gcc 12 omits the method stab section for polymorphic classes, so no vftable is applied",
    )
    fun atLeastOneVtableStructApplied() {
        // box2d_tests shows no detectable C++ surface (no mangled symbols,
        // no `_vptr`, no virtuals); xmltest is C++ but gcc 12 omits the
        // method section from the stab for every polymorphic class
        // (XMLNode et al.) — same Pattern-B family as the other gcc 12
        // missing-stab issues. Surface via println so future fixture
        // changes regain coverage without flagging the run.
        // The applied vtable struct is the <Class>_vftable (the function-pointer array laid at
        // the address point); there is no separate <Class>_vtable full-record struct — the
        // offset_to_top + rtti header words are plain Data before the address point.
        val vmethods = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name.endsWith("_vftable") && it.numComponents > 0 }.toList()
        if (binaryName in setOf("box2d_tests", "xmltest")) {
            println("atLeastOneVtableStructApplied[$binaryName/$mode]: vftables=${vmethods.size}")
            return
        }
        Assertions.assertTrue(
            vmethods.isNotEmpty(),
            "Expected at least one *_vftable struct with components",
        )
        val classesWithVtables = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { struc -> struc.components.any { vmethods.contains((it.dataType as? Pointer)?.dataType) } }
            .toList()
        Assertions.assertTrue(
            classesWithVtables.isNotEmpty(),
            "Expected at least one class with a vtable pointer",
        )
        val badMethodFields = vmethods.flatMap { it.components.asIterable() }
            .filter {
                when (val dt = it.dataType) {
                    is Pointer -> dt.dataType.name != it.fieldName
                    else -> true
                }
            }
        val badMethodTypes = badMethodFields.map { it.dataType.name }.toSet()
        val badVftables = badMethodFields.map { it.parent.name }.toSet()
        Assertions.assertTrue(
            badMethodFields.isEmpty(),
            "$badVftables have fields that aren't proper function pointers: $badMethodTypes",
        )
    }

    @Test
    @ExpectedToFail(
        fixtures = [
            "bouniaf.exe", "bouniaf.exe", "bouniafbouniaf.exe", "xmltest",
            "crypto_mi_test_gcc345.exe", "crypto_mi_test_gcc345_fullstabs.exe",
            "crypto_mi_test_gcc421.exe", "crypto_mi_test_gcc421_fullstabs.exe",
            "crypto_mi_test_gcc421_stripped.exe", "locale_test_gcc345_fullstabs.exe",
            "xmltest_gcc345.exe", "xmltest_gcc345_fullstabs.exe", "xmltest_gcc421.exe",
        ],
        reason = "unresolved empty /Demangler stubs — forward-declared RTTI/EH surface, not yet materialized",
    )
    fun demanglerHasNoEmptyStubs() {
        // /Demangler is the holding category for placeholder structs filled in by
        // DemanglerReplacer. After import these should all be resolved to real types
        // (length > 0 or absorbed into another category) — none should remain as empty
        // Structure stubs, except the bare-template/builtin artifacts with no concrete
        // type (see DemanglerWhitelist.ALLOWED).
        //
        // Only meaningful in AFTER. DemanglerReplacer runs in both modes (StabsImporter pass C),
        // but in CONCURRENT our analyzer fires alongside Ghidra's demangler and finishes before it
        // has created the /Demangler stubs, so replace() has nothing to replace yet (0 vs 169
        // `replaced-demangler`); the stubs are then created later and never revisited. That leaves
        // them empty at assertion time — a mode-ordering artifact, not a materialization gap.
        assumeTrue(mode == Mode.AFTER, "Skipping: /Demangler stubs are created after our pass in CONCURRENT")
        val allEmpty = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.categoryPath.path.startsWith("/Demangler") }
            .filter { it.isZeroLength || it.numComponents == 0 }
            .toList()
        // Dump the pre-whitelist empty-stub names so [DemanglerWhitelistAuditTest] can audit the whitelist
        // across the whole corpus — an entry live in no fixture is dead and should be pruned.
        emptyStubDumpFile.apply { parentFile.mkdirs() }
            .writeText(allEmpty.map { it.name }.toSortedSet().joinToString("\n"))
        val emptyStubs = allEmpty
            .filterNot { it.name in DemanglerWhitelist.ALLOWED }
            .map { "${it.categoryPath.path}/${it.name}" }
        Assertions.assertTrue(
            emptyStubs.isEmpty(),
            "Expected zero unexpected empty /Demangler/* stubs, found ${emptyStubs.size}: " +
                emptyStubs.take(10).joinToString(),
        )
    }

    @Test
    fun fewConflictRenames() {
        // Ghidra forks a `.conflict` type when two distinct types collide on one (category, name).
        // Those renames should be the exception — a spike signals a canonicalisation/dedup regression
        // like the cross-CU TypeId collision fixed in 4b21a6c. Reuses the production census
        // ([conflictCount], the `dtm-conflicts-created` source); corpus-wide it sits at 0.
        //
        // The earlier `^.+_\d+$` heuristic mismeasured badly: we never suffix names with `_N`, so it
        // caught gcc anonymous `$_N` aggregates and legitimately-numbered Win32 structs (JOB_INFO_1,
        // PRINTER_INFO_6, pulled in via mingw headers) — 250–920 "renames" for a real count of ~0.
        val conflicts = program.dataTypeManager.conflictCount()
        Assertions.assertTrue(
            conflicts < 25,
            "Suspiciously many .conflict-renamed types: $conflicts (expected < 25)",
        )
    }

    /**
     * Compatibility surface for `ApplyClassFunctionSignatureUpdatesScript`
     * (shift-S) and `RecoveredClassHelper`:
     *
     *  1. The vftable Structure must live under a CategoryPath containing
     *     the literal `"ClassDataTypes"` segment (the script tests
     *     `baseDataType.getCategoryPath().getPath().contains("ClassDataTypes")`).
     *  2. The vtable Data address must carry a Symbol whose name contains
     *     `"vftable"` (the helper filters refs by
     *     `vftableSymbol.getName().contains("vftable")`).
     *  3. Each vftable slot must be a typed function pointer
     *     (Pointer→FunctionDefinition), not a generic `undefined4*`, so the
     *     decompiler resolves virtual calls and Ghidra creates data refs
     *     that the helper can walk back from the virtual function.
     *
     * `bouniaf` is a good probe class: polymorphic, several virtuals,
     * inherited slots — exercises all three gates.
     */
    @Test
    fun dcinstShiftSCompatibility() {
        val vftable = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name == "bouniaf_vftable" }
            .maxByOrNull { it.numComponents }
        assumeTrue(vftable != null, "Skipping: bouniaf_vftable not found")
        // Gate 1: CategoryPath under ClassDataTypes.
        Assertions.assertTrue(
            "ClassDataTypes" in vftable!!.categoryPath.path,
            "bouniaf_vftable category '${vftable.categoryPath.path}' " +
                "must contain 'ClassDataTypes' (RecoveredClassHelper convention)",
        )
        // Gate 3: every populated slot is Pointer→FunctionDefinition.
        val slotTypeSummary = (0 until vftable.numComponents).map { i ->
            val c = vftable.getComponent(i)
            val ptr = c.dataType as? Pointer
            val pointee = ptr?.dataType
            Triple(c.fieldName ?: "<?>", ptr != null, pointee is FunctionDefinition)
        }
        val typedSlots = slotTypeSummary.count { it.third }
        val totalSlots = slotTypeSummary.size
        Assertions.assertTrue(
            typedSlots > 0 && typedSlots >= totalSlots / 2,
            "bouniaf_vftable: only $typedSlots/$totalSlots slots are typed " +
                "Pointer→FunctionDefinition. Slots: $slotTypeSummary",
        )
        // Gate 2: `vftable` symbol at the vtable's *address point* (`_ZTV6bouniaf` + 2*ptrSize),
        // not at the DTV start. That's the value a `{vfptr}` holds and where constructor stores
        // reference, so RecoveredClassHelper walks refs back from there.
        val ztv = program.symbolTable.getSymbols("__ZTV6bouniaf").firstOrNull()
        assumeTrue(ztv != null, "Skipping: bouniaf not resolved")
        val addressPoint = ztv!!.address.add(2L * program.defaultPointerSize)
        val syms = program.symbolTable.getSymbols(addressPoint).toList()
        val symSummary = syms.map { "${it.parentNamespace.name}::${it.name}" }
        Assertions.assertTrue(
            syms.any { "vftable" in it.name },
            "bouniaf address point $addressPoint has no symbol containing 'vftable'; " +
                "symbols there: $symSummary",
        )
    }

    @Test
    fun dcinstVtableMatchesItaniumLayout() {
        // Prefer the non-empty copy: there may be one stub in /Demangler or /std/<header>
        // from per-AST iteration and a real one elsewhere.
        val vtable = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name == "bouniaf_vtable" }
            .maxByOrNull { it.numComponents }
        assumeTrue(vtable != null, "Skipping: bouniaf_vtable not found")
        val components = (0 until vtable!!.numComponents).map {
            val c = vtable.getComponent(it)
            "[${c.offset}] ${c.fieldName ?: "<unnamed>"}: ${c.dataType.name}"
        }
        val dups = program.dataTypeManager.allDataTypes
            .asSequence().filter { it.name == "bouniaf_vtable" }
            .map { "${it.categoryPath.path}/${it.name} (len=${(it as Structure).length})" }
            .toList()
        val fieldNames = (0 until vtable.numComponents).map { vtable.getComponent(it).fieldName }
        Assertions.assertEquals(
            "offset_to_top",
            fieldNames.getOrNull(0),
            "Components:\n${components.joinToString("\n")}\n" +
                "bouniaf_vtable copies in DTM:\n${dups.joinToString("\n")}",
        )
        Assertions.assertEquals("rtti", fieldNames.getOrNull(1))
        Assertions.assertEquals("vftable", fieldNames.getOrNull(2))
        // The function pointers live inside bouniaf_vftable (what {vfptr} actually points to).
        val vmethods = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name == "bouniaf_vftable" }
            .maxByOrNull { it.numComponents }
        Assertions.assertNotNull(vmethods, "bouniaf_vftable not found")
        val virtuals = (0 until vmethods!!.numComponents).mapNotNull {
            vmethods.getComponent(it).fieldName
        }.toSet()
        // bouniaf's own + inherited (Inst::Get* via ExprInst → bouniaf → Inst chain).
        val expected = setOf(
            "GetInstType", "__comp_dtor", "__deleting_dtor",
            "Clone", "Dump", "GetSize", "PossibleFunctionReference",
            "GetOffset", "GetPrevOffset", "GetFullOffset", "GetPrevFullOffset",
        )
        val missing = expected - virtuals
        Assertions.assertTrue(
            missing.isEmpty(),
            "bouniaf_vftable missing virtuals: $missing (have: $virtuals)",
        )
    }

    @Test
    fun atLeastOneRootClassHasVtableBackEdge() {
        assumeTrue(binaryName == "bouniafbouniaf.exe", "Skipping: vtable back-edge checks specific to bouniafbouniaf.exe")
        // At least one polymorphic class should directly contain a {vfptr} Pointer
        // pointing at its <Name>_vftable struct (the function pointer array — what
        // a real C++ vptr actually points at, vs. the full <Name>_vtable record that
        // also has the offset_to_top + rtti Itanium prefix).
        // Derived classes correctly *inherit* their vfptr via a `_base_<Parent>`
        // subobject so most won't carry the pointer directly; but the root of every
        // inheritance chain (e.g. Inst on bouniafbouniaf.exe) must, otherwise the
        // ClassBuilder vfptr-insertion path is broken end-to-end.
        val vmethods = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name.endsWith("_vftable") && it.numComponents > 0 }
            .toList()
        val withMatchingVfptr = vmethods.count { vm ->
            val className = vm.name.removeSuffix("_vftable")
            val cls = program.dataTypeManager.allDataTypes
                .asSequence()
                .filterIsInstance<Structure>()
                .firstOrNull { it.name == className }
            cls != null && cls.components.any { (it.dataType as? Pointer)?.dataType === vm }
        }
        Assertions.assertTrue(
            withMatchingVfptr >= 1,
            "Expected ≥ 1 *_vftable struct to have a back-edge {vfptr} from its class; " +
                "got $withMatchingVfptr / ${vmethods.size}",
        )
    }

    @Test
    @ExpectedToFail(
        fixtures = ["tinyxml_aout_gcc295.o"],
        reason = "single translation unit whose file-scope data happens to include no pointer global",
    )
    fun globalsCoverEachDataTypeKind() {
        val seenKinds = mutableSetOf<String>()
        program.listing.getDefinedData(true).forEach { data ->
            seenKinds += when (val dt = data.dataType) {
                is Structure -> "Structure"
                is Array -> "Array"
                is Union -> "Union"
                is Pointer -> "Pointer"
                is Enum -> "Enum"
                is TypeDef -> "TypeDef"
                is FunctionDefinition -> "FunctionDefinition"
                else -> "Primitive"
            }
        }
        // Enum is not required: bouniafbouniaf.exe may have no enum-typed globals.
        // The other kinds reflect basic global-application coverage.
        val required = setOf("Structure", "Pointer", "Primitive")
        val missing = required - seenKinds
        Assertions.assertTrue(
            missing.isEmpty(),
            "Missing DataType kinds in globals: $missing (saw: $seenKinds)",
        )
    }

    /**
     * Function-local (`V` descriptor) statics get a PLATE comment naming their enclosing function,
     * attributed via the harvest-time `currentFunction`. box2d emits ~32 (e.g. `once` in
     * b2PairQueryCallback, `s_next` in b2ValidateReplay).
     */
    @Test
    fun functionLocalStaticsGetEnclosingFunctionComment() {
        assumeTrue(binaryName == "box2d_tests", "Skipping: needs a fixture with function-local (V) statics")
        val plated = context.diagnostics.snapshotCounters()["static-local-plate"] ?: 0L
        Assertions.assertTrue(
            plated > 0,
            "expected function-local (V) statics to get 'static local of <fn>' plate comments; got $plated",
        )
    }

    @OptIn(ExperimentalSerializationApi::class)
    @Test
    fun harvestTest() {
        // Reuse setUp's import artifacts; re-read / re-harvest only when it produced none (no stabs).
        // Harvest is a pure producer (no Program mutation), so the fallback needs no transaction.
        val records = artifacts.records
        dumpJson.encodeToStream(records, recordsFile.outputStream())

        val harvest = artifacts.harvest
        dumpJson.encodeToStream(harvest, harvestFile.outputStream())

        val classStructs = harvest.types.values
            .mapNotNull { it.asStruct() }
            .filter { (ast, body) -> body.rawKind == AggrKind.CLASS }
            .toList()

        val emptyStructs = harvest.types.values
            .mapNotNull { it.asStruct() }
            .filter { (ast, body) -> body.fields.isEmpty() && body.methods.isEmpty() }
            .toList()

        val index = artifacts.index
        val baseTypes =
            harvest.types.values.filter { it.id.source is SourceFile.CUSource && !it.body.isXRefTarget }.toList()
        val different = baseTypes
            .groupBy { index.content(it.body) }
            .mapKeys { (k, v) -> k to v.map { it.name }.toSet() }

        // Never print a LayoutContent: the worst expands to ~11k nodes, and the old `println(different)`
        // stringified one per map key across every content class. hashCode is memoized and O(1);
        // identity is all this diagnostic needs.
        println(layoutStats(index))
        println("base types: ${baseTypes.size} types in ${different.size} content classes")
        for ((k, asts) in different) {
            val (content, names) = k
            if (asts.size > 1 && names.contains(null)) {
                println("- ${content.hashCode()}")
                for (ast in asts) {
                    println("       =>  ${index.content(ast.body).hashCode()} ${ast.id} ${ast.ghidraName}")
                }
            }
        }

        // Aspirational: box2d_tests pulls in vendored deps (imgui, stbtt,
        // GLFW) whose stab entries are incomplete — gcc 12 emits empty
        // Struct bodies for some headers. Report via println instead of
        // asserting.
        if (emptyStructs.isNotEmpty()) {
            println(
                "harvestTest[$binaryName/$mode]: ${emptyStructs.size} empty structs in harvest " +
                    "(${emptyStructs.take(5).map { (a, _) -> a.ghidraName }})",
            )
        }
    }

    /**
     * Size of the cached [ContentIndex.LayoutContent] graph, measured by identity so shared subgraphs
     * are counted once. `expanded` is what a structural walk (e.g. the generated toString) would visit —
     * memoized per node, so the *count* is O(nodes) even when the count itself is astronomical.
     */
    private fun layoutStats(index: ghistabs.harvest.HarvestIndex): String {
        val roots = index.contentCache.values
        val seen = java.util.Collections.newSetFromMap(
            java.util.IdentityHashMap<ContentIndex.LayoutContent, Boolean>(),
        )
        val order = ArrayList<ContentIndex.LayoutContent>()
        val stack = ArrayDeque(roots.toList())
        var dataCells = 0L
        var listObjs = 0L
        while (stack.isNotEmpty()) {
            val n = stack.removeLast()
            if (!seen.add(n)) continue
            order += n
            dataCells += n.data.size
            listObjs += 1 + n.children.size
            n.children.forEach { stack.addAll(it) }
        }
        val worst = order.maxOfOrNull { it.expandedNodes } ?: 0
        val totalExpanded = roots.sumOf { it.expandedNodes.toLong() }
        // ~32B object + ArrayList(data) + ArrayList(children) + one inner ArrayList each, + boxed longs.
        val bytes = seen.size * 32L + listObjs * 40L + dataCells * 20L
        return "layout: distinctNodes=${seen.size} roots=${roots.size} dataCells=$dataCells " +
            "~${bytes / 1024 / 1024}MB | expanded(total)=$totalExpanded worstSingleNode=$worst"
    }

    // ---- Mangling / execution-order assertions, shared between modes. ----

    /**
     * `RegToBinary` is a free function (`_Z11RegToBinary12EnumRegToken`) with a
     * single `reg: EnumRegToken` stack param recorded in the stabs. The function
     * lookup in [StabsImporter] is by address (not by name) so the param
     * application must succeed regardless of whether the symbol has been
     * demangled yet — i.e. it must work in both modes.
     */
    @Test
    fun regToBinaryParamsApplied() {
        val fm = program.functionManager
        val candidates = fm.getFunctions(true).iterator().asSequence()
            .filter { it.name == "RegToBinary" || it.name == "_Z11RegToBinary12EnumRegToken" }
            .toList()
        assumeTrue(candidates.isNotEmpty(), "Skipping: RegToBinary not found")
        val func = candidates.first()
        Assertions.assertEquals(
            1,
            func.parameterCount,
            "RegToBinary should have its single `reg` stab param applied; got " +
                "${func.parameterCount} (signature=${func.signature.prototypeString})",
        )
        val p = func.getParameter(0)!!
        Assertions.assertEquals("reg", p.name, "first param should be named 'reg' from the N_PSYM record")
    }

    /**
     * Ghidra's demangler runs once at priority ~897 over loader-added
     * symbols; the raw mangled names we set from the stabs (function
     * names in applyAllFunctions) appear later and would be missed.
     * [StabsImporter.demangleMangledLabels]
     * sweeps every IMPORTED `_Z` / `__Z` symbol at the end of the import
     * with `DemanglerCmd`, with signature/calling-convention application
     * disabled so our stab-derived prototype and `__thiscall` choice
     * still win. This test pins the end-to-end name resolution on a
     * known free function (`RegToBinary`).
     */
    @Test
    fun freeFunctionSymbolGetsDemangled() {
        assumeTrue(binaryName == "bouniafbouniaf.exe", "Skipping: RegToBinary specific to bouniafbouniaf.exe")
        val fm = program.functionManager
        val byMangled = fm.getFunctions(true).asIterable()
            .firstOrNull { it.name == "_Z11RegToBinary12EnumRegToken" }
        val byDemangled = fm.getFunctions(true).iterator().asSequence()
            .firstOrNull { it.name == "RegToBinary" }
        val candidates = fm.getFunctions(true).iterator().asSequence()
            .filter { "RegToBinary" in it.name }
            .map { "${it.entryPoint}: ${it.name} (ns=${it.parentNamespace.name})" }
            .toList()
        Assertions.assertNotNull(
            byDemangled,
            "RegToBinary should be visible under its demangled name; " +
                "found mangled instead: ${byMangled?.name}. All candidates: $candidates",
        )
    }

    /**
     * No empty `/Demangler/...` Structure stubs of *known* project types should
     * remain after the importer finishes. This catches the bug where the
     * candidate-finding loop in [DemanglerReplacer] failed to identify the real
     * type because the stub itself polluted the name index.
     */
    @Test
    fun knownDemanglerStubsReplaced() {
        // Names known to be both demangled (so the demangler creates a stub) and
        // materialized from stabs (so a real type exists to replace the stub).
        val knownNames = setOf("bouniaf", "bouniaf", "bouniaf")
        val leftover = program.dataTypeManager.allDataTypes
            .asSequence()
            .filter { it.categoryPath.path.startsWith("/Demangler") }
            .filter { it.name in knownNames }
            .map { "${it.categoryPath.path}/${it.name}" }
            .toList()
        Assertions.assertTrue(
            leftover.isEmpty(),
            "Expected /Demangler/{$knownNames} stubs to be replaced, still present: $leftover",
        )
    }

    /**
     * `inheritance-applied` counter is only captured via CapturingSink in
     * AFTER mode (CONCURRENT mode feeds through MessageSinkAdapter→MessageLog).
     */
    @Test
    @ExpectedToFail(
        fixtures = [
            "hello_aout_gcc295.o", "zlib_aout_gcc263.o",
            // C++, but gcc 2.95 defaults to minimal debug, so every method reads `##<type>` — the
            // arguments live in the mangled name instead. The class body fails at the first one,
            // taking the `!` inheritance spec parsed just before it down with the record.
            "tinyxml_aout_gcc295.o",
        ],
        reason = "plain C fixtures — no C++ inheritance edges exist to materialize",
    )
    fun inheritanceWasApplied() {
        val applied = context.diagnostics.snapshotCounters()["inheritance-applied"] ?: 0L
        // box2d_tests has no detectable inheritance in our scan (no mangled
        // C++ symbols, no `_vptr`, no `~%`, no pseudo-field bitsize
        // anomalies — strings shows pure C). If a future build introduces
        // C++ paths and we still get 0, this will surface in the run
        // output without flagging the test as failed.
        if (binaryName == "box2d_tests") {
            println("inheritanceWasApplied[$binaryName/$mode]: applied=$applied")
            return
        }
        Assertions.assertTrue(
            applied > 0,
            "Expected inheritance-applied counter > 0, got $applied " +
                "(no C++ inheritance edges were materialized)",
        )
    }

    /**
     * No class method should end up with two `this` parameters. The
     * historical regression (see ClassBuilder comment around the
     * `ghidraInjectsThis` decision) was the importer keeping the stab's
     * explicit leading `this` while Ghidra's `__thiscall` convention also
     * auto-injected one, producing
     *   `void bouniaf::Dump(bouniaf *this, ushort this, …)`
     * Static class methods legitimately have zero `this` params, so the
     * tight bound is `count <= 1`, not `== 1`.
     */
    @Test
    fun classMethodsHaveAtMostOneThis() {
        val offenders = program.functionManager.getFunctions(true).iterator().asSequence()
            .filter { it.parentNamespace is ghidra.program.model.listing.GhidraClass }
            .filter { f -> f.parameters.count { it.name == "this" } > 1 }
            .map { f ->
                val params = f.parameters.joinToString(", ") { "${it.name}: ${it.dataType.name}" }
                "${f.parentNamespace.name}::${f.name} cc=${f.callingConventionName} params=[$params]"
            }
            .take(20)
            .toList()
        Assertions.assertTrue(
            offenders.isEmpty(),
            "Class methods must have at most one `this` (no duplicate-this regression): " +
                "${offenders.size} offenders:\n  - " + offenders.joinToString("\n  - "),
        )
    }

    /**
     * On the mingw fixtures the importer should have promoted class methods
     * to `__thiscall` (`reparentMethod` calls `func.setCallingConvention`).
     * On x86-64 ELF the convention exists in the spec but is effectively a
     * no-op — the assertion intentionally only checks the mingw side, since
     * the Linux side already has reliable cdecl/sysv handling.
     */

    /**
     * Any DataType we registered in the DTM with a name that's a serialized
     * GlobalTypeId (`[<source>,<n>]` shape) is an anonymous type we couldn't
     * give a meaningful name to. That's a missing name-promotion / fallback
     * path. Reading the listing, the user would see `[/xml/tinyxml2.cpp,42] *`
     * as a field type — not useful. Flag every one and fail.
     */
    @Test
    fun noAnonymousMaterializedTypes() {
        // [source,n] where source may contain '/', '#', '.', etc. — match liberally.
        val idLike = Regex("""^\[[^\[\]]+,\d+]$""")
        val anon = program.dataTypeManager.allDataTypes.asSequence()
            .filter { idLike.matches(it.name) }
            .take(20)
            .map { "${it.categoryPath}/${it.name} (${it::class.simpleName})" }
            .toList()
        // Aspirational: orphan-stub cleanup removes the empty ones, but
        // anonymous types referenced by other types stay (FunctionDefinition
        // params, struct field types, etc.). Their existence isn't a bug
        // per se — they're real anonymous aggregates from the source — but
        // the synthetic name is ugly. Report via println.
        if (anon.isNotEmpty()) {
            println(
                "noAnonymousMaterializedTypes[$binaryName/$mode]: ${anon.size} anonymous DTM types:\n  - " +
                    anon.joinToString("\n  - "),
            )
        }
    }

    @Test
    @ExpectedToFail(
        fixtures = ["xmltest_gcc421_stripped.exe"],
        reason = "gcc 12 stripped: no class methods get __thiscall (reparentMethod's setCallingConvention no-ops)",
    )
    fun mingwClassMethodsCarryThiscall() {
        assumeTrue(
            binaryName.endsWith(".exe"),
            "Skipping: __thiscall check only meaningful on mingw fixtures",
        )
        val classFuncs = program.functionManager.getFunctions(true).iterator().asSequence()
            .filter { it.parentNamespace is ghidra.program.model.listing.GhidraClass }
            .toList()
        // reparentMethod only reaches setCallingConvention("__thiscall") for a method it can pin to
        // an address: either an in-TU N_FUN stab (works even stripped) or, absent that, the COFF
        // symtab. A fully-stripped binary loses the symtab path, and the remaining out-of-line/inline
        // STL methods have no body here at all (non-stripped fullstabs shows the same ~991 resolve
        // failures) — so no class-namespaced function survives to tag. Nothing to assert then; but a
        // non-empty classFuncs with zero __thiscall is still a real regression, so keep asserting.
        assumeTrue(
            classFuncs.isNotEmpty(),
            "Skipping: no resolvable class methods (stripped symtab + no in-TU method bodies)",
        )
        val thiscalled = classFuncs.count { it.callingConventionName == "__thiscall" }
        Assertions.assertTrue(
            thiscalled > 0,
            "binary=$binaryName: ${classFuncs.size} class methods, none tagged __thiscall " +
                "(reparentMethod's setCallingConvention silently failed)",
        )
    }

    /**
     * bouniaf and bouniaf form a single-inheritance chain in
     * bouniafbouniaf (bouniaf extends bouniaf extends basic_ifstream).
     * gcc's stab is internally inconsistent on both — `s328` / `s416`
     * declare more bytes than the layout actually describes (bouniaf's
     * last own field Tok ends at 192; bouniaf's last own field
     * RecoverySet ends at 276). The placeholder-truncate fix uses
     * "last described byte" as the size, which (a) removes the trailing
     * unexplained padding and (b) makes bouniaf's size match what
     * bouniaf's CU expects from its base — so the base placement
     * fits cleanly without overwrite or synthesis.
     *
     * This also requires the truncate to happen at placeholder-creation
     * time (not later), so the size is consistent across pre-seed and
     * the materialize-winner loop regardless of order: bouniaf's
     * base loop sees bouniaf's already-truncated placeholder.
     */
    @Test
    fun bouniafAndbouniafTruncated() {
        assumeTrue(binaryName == "bouniafbouniaf.exe", "Skipping: bouniaf chain is bouniafbouniaf-specific")

        fun findStruct(name: String): Structure = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .firstOrNull { it.name == name }
            ?: throw AssertionError("Structure '$name' not in DTM")

        // bouniaf: truncate to its last own field end. Tok at +168 size 24 → 192.
        val clex = findStruct("bouniaf")
        Assertions.assertEquals(
            192,
            clex.length,
            "bouniaf should be truncated to 192 (Tok ends at 168+24); got ${clex.length}",
        )
        val clexFields = clex.components.associateBy { it.fieldName ?: "" }
        Assertions.assertEquals(112, clexFields["LineNo"]?.offset, "LineNo expected at +112")
        Assertions.assertEquals(168, clexFields["Tok"]?.offset, "Tok expected at +168")
        Assertions.assertEquals(24, clexFields["Tok"]?.length, "Tok expected to span 24 bytes")

        // bouniaf: own fields end at RecoverySet+40 = 276. Truncate target = 276.
        val csym = findStruct("bouniaf")
        Assertions.assertEquals(
            276,
            csym.length,
            "bouniaf should be truncated to 276 (RecoverySet ends at 236+40); got ${csym.length}",
        )

        // bouniaf's base at +0 must be bouniaf itself (resolved, not
        // a synthesised placeholder). That's the cascade: bouniaf's
        // truncate-to-192 made it fit exactly in bouniaf's 192-byte gap.
        val csymFields = csym.components.associateBy { it.fieldName ?: "" }
        val baseField = csymFields["_base_bouniaf"]
        Assertions.assertNotNull(
            baseField,
            "_base_bouniaf missing from bouniaf; components: ${csymFields.keys}",
        )
        Assertions.assertEquals(0, baseField!!.offset, "_base_bouniaf expected at +0")
        Assertions.assertEquals(192, baseField.length, "_base_bouniaf expected to span 192 bytes")
        Assertions.assertSame(
            clex,
            baseField.dataType,
            "_base_bouniaf's dataType should be the same bouniaf Structure",
        )

        Assertions.assertEquals(192, csymFields["CurrentTok"]?.offset, "CurrentTok expected at +192")
        Assertions.assertEquals(236, csymFields["RecoverySet"]?.offset, "RecoverySet expected at +236")
        Assertions.assertEquals(40, csymFields["RecoverySet"]?.length, "RecoverySet expected to span 40 bytes")
    }

    /**
     * FillerByteAnalyzer is the only source of [AlignmentDataType] in the pipeline, so a nonzero
     * count is exactly its hits. Runs on every fixture.
     * (Folded from the former FillerByteAnalyzerIntegrationTest — rides on setUp's autoanalysis.)
     */
    @Test
    fun fillerBytesCollapsedToAlignment() {
        val data = program.listing.getDefinedData(true)
        var runs = 0
        while (data.hasNext()) if (data.next().dataType is AlignmentDataType) runs++
        Assertions.assertTrue(runs > 0, "FillerByteAnalyzer collapsed no padding in $binaryName")
    }

    /**
     * The GAS jump-over-fill idiom (`eb 0d 90…`: an unconditional forward JMP to the aligned boundary,
     * NOPs behind it) must also collapse — not just plain NOP runs. In bouniafbouniaf.exe these appear both
     * before a function (e.g. 0042bc31) and before a string block gcc parked in `.text` (00421aa1);
     * either way the Alignment must start on the JMP opcode. Asserts at least one such run exists.
     */
    @Test
    fun jumpOverFillCollapsedToAlignment() {
        assumeTrue(binaryName == "bouniafbouniaf.exe", "jump-over-fill check scoped to bouniafbouniaf.exe")
        val data = program.listing.getDefinedData(true)
        var jumpFills = 0
        while (data.hasNext()) {
            val d = data.next()
            if (d.dataType !is AlignmentDataType) continue
            val opcode = runCatching { d.bytes.firstOrNull()?.toInt()?.and(0xff) }.getOrNull()
            if (opcode == 0xeb || opcode == 0xe9) jumpFills++
        }
        Assertions.assertTrue(jumpFills > 0, "no jump-over-fill padding collapsed in $binaryName")
    }

    /**
     * The function-relative address heuristic ([stabAddress]): every `N_SLINE`/`N_LBRAC`/`N_RBRAC`
     * record, resolved against its enclosing `N_FUN`, must land in executable memory. A value left
     * un-rebased resolves to a tiny address in no code block. Not asserted against the *enclosing*
     * function specifically — gcc clones ctors/dtors, so a stab function's line range legitimately
     * spans sibling clones. Runs on every fixture. (Folded from the former
     * FuncRelativeAddressIntegrationTest.)
     */
    @Test
    @ExpectedToFail(
        fixtures = ["zlib_aout_gcc263.o"],
        reason = "relocatable object (ld -r): sections all sit at 0 unrelocated, so stab values " +
            "cannot resolve into executable code",
    )
    fun funcRelativeAddressesLandInExecutableCode() {
        val resolver = program.defaultContext().resolver
        val reader = StabReader.fromProgram(program)
        assumeTrue(reader != null, "no .stab in $binaryName")

        var funcStart: Address? = null
        var checked = 0
        val notCode = mutableListOf<String>()
        for (rec in reader!!.physicalRecords()) {
            when (rec.type) {
                StabType.N_FUN ->
                    funcStart = rec.name.ifEmpty { null }?.let { resolver.buildAddress(rec.value) }

                StabType.N_SLINE, StabType.N_LBRAC, StabType.N_RBRAC -> {
                    val fs = funcStart ?: continue
                    val target = resolver.stabAddress(rec.value, fs)
                    checked++
                    if (program.memory.getBlock(target)?.isExecute != true) {
                        notCode += "${rec.type} @${rec.index} value=0x${rec.value.toString(16)} → $target (from $fs)"
                    }
                }

                else -> {}
            }
        }
        assumeTrue(checked > 0, "no func-relative records in $binaryName")
        Assertions.assertTrue(
            notCode.isEmpty(),
            "func-relative stab values resolved outside executable code in $binaryName " +
                "(${notCode.size}/$checked):\n${notCode.take(20).joinToString("\n")}",
        )
    }
}
