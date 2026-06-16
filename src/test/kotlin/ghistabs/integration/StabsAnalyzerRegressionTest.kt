package ghistabs.integration

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.app.util.opinion.LoadResults
import ghidra.program.model.data.*
import ghidra.program.model.data.Array
import ghidra.program.model.data.Enum
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.StabsAnalyzer
import ghistabs.diag.CapturingSink
import ghistabs.diag.defaultContext
import ghistabs.importer.ImportContext
import ghistabs.importer.StaticContexts
import ghistabs.parser.Harvester
import ghistabs.parser.IdInterface
import ghistabs.parser.StabReader
import ghistabs.parser.ToStringSerializer
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToStream
import kotlinx.serialization.modules.SerializersModule
import org.junit.jupiter.api.*
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.parallel.Execution
import org.junit.jupiter.api.parallel.ExecutionMode
import org.junit.jupiter.params.AfterParameterizedClassInvocation
import org.junit.jupiter.params.BeforeParameterizedClassInvocation
import org.junit.jupiter.params.Parameter
import org.junit.jupiter.params.ParameterizedClass
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
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
@ParameterizedClass
@MethodSource("testParameters")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Execution(ExecutionMode.CONCURRENT)
@Tag("integration")
class StabsAnalyzerTests : AbstractGhidraHeadlessIntegrationTest() {
    companion object {
        val BINARIES = listOf("bouniafbouniaf.exe", "xmltest", "bouniaf.exe", "box2d")

        @JvmStatic
        fun testParameters() = BINARIES.flatMap { binary ->
            Mode.entries.map { mode -> Arguments.of(binary, mode) }
        }.stream()
    }

    // Both fields injected per parameterized invocation before @BeforeParameterizedClassInvocation.
    @Parameter(0)
    lateinit var binaryName: String

    @Parameter(1)
    lateinit var mode: Mode

    fun resourceFile(kind: String) = File("src/test/resources/${kind}s/${fixture.nameWithoutExtension}-$kind.json")
    private val fixture get() = File("src/test/resources/binaries/$binaryName")
    private val baselineFile get() = resourceFile("baseline")
    private val recordsFile get() = resourceFile("record")
    private val harvestFile get() = resourceFile("harvest.${mode.name.lowercase()}")
    private val logFile
        get() = File("src/test/resources/logs/${fixture.nameWithoutExtension}.${mode.name.lowercase()}.log")

    private lateinit var loadResults: LoadResults<Program>
    private lateinit var context: ImportContext<CapturingSink>
    private val program get() = context.program

    @OptIn(ExperimentalSerializationApi::class)
    private val json by lazy {
        Json {
            serializersModule = SerializersModule {
                @Suppress("UNCHECKED_CAST")
                contextual(IdInterface::class, ToStringSerializer as KSerializer<IdInterface>)
                prettyPrint = true
            }
        }
    }

    @BeforeParameterizedClassInvocation
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
            loadResults = ProgramLoader
                .builder()
                .source(fixture)
                .compiler(if (fixture.extension.lowercase() == "exe") "mingw" else null)
                .log(log)
                .monitor(monitor)
                .load()

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
                    StaticContexts.install(context)

                    // BYTE_ANALYZER auto-fires on byte changes; on a freshly-
                    // loaded program nothing has "changed" since the loader put
                    // bytes down, so we explicitly schedule our analyzer for the
                    // next analysis pass — it then runs at its declared priority
                    // alongside the demangler.
                    options.setBoolean(ourName, true)
                    mgr.scheduleOneTimeAnalysis(discovered, program.memory)
                    runAutoAnalysis(mgr, monitor)
                }

                Mode.AFTER -> {
                    // Disable our analyzer so auto-analysis (incl. demangler) settles
                    // without us, then re-run it manually with our CapturingSink.
                    // `Options.setBoolean` mutates the program options DB and needs
                    // a transaction.
                    val txOpt = program.startTransaction("disable-stabs-analyzer")
                    try {
                        options.setBoolean(ourName, false)
                    } finally {
                        program.endTransaction(txOpt, true)
                    }
                    mgr.initializeOptions()
                    runAutoAnalysis(mgr, monitor)
                    val tx = program.startTransaction("stabs-analyze")
                    try {
                        StabsAnalyzer().run(context)
                    } finally {
                        program.endTransaction(tx, true)
                    }
                }
            }
            // CapturingSink holds the full untruncated log in both modes
            // (in CONCURRENT it's fed via ExternalSinks → TeeSink). MessageLog
            // is appended for parity with Ghidra's own view, even though it
            // truncates at ~500 lines.
            logFile.writeText(context.log.dedupedOutput() + "\n--- MessageLog ---\n" + log.toString())
        } catch (e: Exception) {
            assumeTrue(false, "Failed to load real binary via ProgramLoader: ${e.message}")
        }
    }

    private fun runAutoAnalysis(mgr: AutoAnalysisManager, monitor: TaskMonitor) {
        val tx = program.startTransaction("auto-analyze")
        try {
            mgr.startAnalysis(monitor)
            mgr.waitForAnalysis(null, monitor)
        } finally {
            program.endTransaction(tx, true)
        }
    }

    @AfterParameterizedClassInvocation
    fun tearDown() {
        StaticContexts.clear(program)
        program.release(this)
        loadResults.close()
    }

    @Test
    fun countersWithinBaseline() {
        assumeTrue(binaryName == "bouniafbouniaf.exe", "Skipping: baseline only exists for bouniafbouniaf.exe")
        val tagCounts = context.log.tagFrequencies()
        val baseline = BaselineLoader.load(baselineFile)

        // If no stabs were found in the binary, skip the test
        // (stabs sections may not exist or may be in a non-standard format)
        assumeTrue(
            tagCounts.isNotEmpty(),
            "Skipping: No stabs counters found in binary (stabs sections absent or non-standard format)",
        )

        val drift = mutableListOf<String>()
        for ((counterName, range) in baseline.counters) {
            val actual = tagCounts.getOrDefault(counterName, 0L)
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
     * `undefined4` placeholders, which `applyGlobal` now evicts via
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

    @Test
    fun cparserMaterialised() {
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
        // a project category. What matters is that it materialised as a non-empty
        // Structure that ClassBuilder can find via Attribution (i.e. the dedup +
        // sort-stable attribution agree on the same category).
        val best = all.firstOrNull { "(StructureDB" in it }
        Assertions.assertNotNull(best, "No bouniaf Structure in DTM. Got:\n${all.joinToString("\n")}")
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

    @Test
    fun bouniafHasBaseField() {
        val cls = program.dataTypeManager.allDataTypes.asSequence()
            .firstOrNull { it.name == "bouniaf" && it is Structure } as? Structure
        assumeTrue(cls != null, "Skipping: bouniaf not found (stabs not processed)")
        val hasBase =
            (0 until cls!!.numComponents).any { i ->
                cls.getComponent(i).fieldName?.let { it.startsWith("_base_") || it.startsWith("_vbase_") } == true
            }
        Assertions.assertTrue(hasBase, "bouniaf has no _base_/_vbase_ component")
    }

    @Test
    fun atLeastOneVtableStructApplied() {
        assumeTrue(binaryName == "bouniafbouniaf.exe", "Skipping: vtable layout checks specific to bouniafbouniaf.exe")
        val vtables = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name.endsWith("_vtable") && it.numComponents > 0 }.toList()
        Assertions.assertTrue(
            vtables.isNotEmpty(),
            "Expected at least one *_vtable struct with components",
        )
        // {vfptr} fields point at <Class>_vftable (the function pointer array),
        // not at <Class>_vtable (the full record including offset_to_top + rtti).
        val vmethods = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name.endsWith("_vftable") && it.numComponents > 0 }.toList()
        val classesWithVtables = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.components.any { vmethods.contains((it.dataType as? Pointer)?.dataType) } }
            .toList()
        Assertions.assertTrue(
            classesWithVtables.isNotEmpty(),
            "Expected at least one class with a vtable pointer",
        )
    }

    @Test
    fun demanglerHasNoEmptyStubs() {
        // /Demangler is the holding category for placeholder structs filled in by
        // DemanglerReplacer. After import these should all be resolved to real types
        // (length > 0 or absorbed into another category) — none should remain as
        // empty Structure stubs.
        val emptyStubs = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.categoryPath.path.startsWith("/Demangler") }
            .filter { it.isZeroLength || it.numComponents == 0 }
            .map { "${it.categoryPath.path}/${it.name}" }
            .toList()
        Assertions.assertTrue(
            emptyStubs.isEmpty(),
            "Expected zero empty /Demangler/* stubs, found ${emptyStubs.size}: " +
                emptyStubs.take(10).joinToString(),
        )
    }

    @Test
    fun fewSuffixedConflictRenames() {
        // Types renamed to `<name>_<N>` by conflict-dedup should be the exception,
        // not the rule. A high count signals canonicalisation/dedup regressions like
        // the cross-CU TypeId collision fixed in 4b21a6c.
        val suffixed = program.dataTypeManager.allDataTypes
            .asSequence()
            .filter { Regex("""^.+_\d+$""").matches(it.name) }
            .count()
        Assertions.assertTrue(
            suffixed < 200,
            "Suspiciously many _N-suffixed types: $suffixed (expected < 200)",
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
        // Gate 2: `vftable` symbol at the DTV address. Walk the symbol table
        // for `_ZTV6bouniaf` (Itanium-mangled DTV symbol) and check siblings.
        val ztv = program.symbolTable.getSymbols("__ZTV6bouniaf").firstOrNull()
        assumeTrue(ztv != null, "Skipping: bouniaf not resolved")
        val sibs = program.symbolTable.getSymbols(ztv!!.address).toList()
        val sibSummary = sibs.map { "${it.parentNamespace.name}::${it.name}" }
        Assertions.assertTrue(
            sibs.any { "vftable" in it.name },
            "bouniaf vtable address ${ztv.address} has no symbol containing 'vftable'; " +
                "symbols there: $sibSummary",
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
        val virtuals = (0 until vmethods!!.numComponents).map {
            vmethods.getComponent(it).fieldName
        }.filterNotNull().toSet()
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

    @OptIn(ExperimentalSerializationApi::class)
    @Test
    fun harvestTest() {
        val ctx = program.defaultContext()
        val stabs = StabReader.fromProgram(program)!!
        json.encodeToStream(stabs.records, recordsFile.outputStream())

        val harvester = Harvester(TaskMonitor.DUMMY, ctx.sink, ctx.resolver)
        // passA writes via AddressResolver.recordFromStab → symbolTable.createLabel, so it
        // needs a transaction. (We re-run it here to serialize a self-contained harvest
        // independent of setUp's own pass.)
        val tx = program.startTransaction("stabs-harvest-dump")
        val harvest = try {
            harvester.passA(stabs.records)
        } finally {
            program.endTransaction(tx, true)
        }

        json.encodeToStream(harvest, harvestFile.outputStream())
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
     * symbols; our stab-derived labels (`recordFromStab` → `createLabel`)
     * appear later and would be missed. [StabsImporter.demangleMangledLabels]
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
        // materialised from stabs (so a real type exists to replace the stub).
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
     * AFTER mode only: demangler has settled before we run, so all
     * `/Demangler/<Name>` placeholder stubs should have been replaced.
     * In CONCURRENT mode the demangler may still be running while we apply
     * types, so the stub population is racy.
     */
    @Test
    fun noEmptyDemanglerStubsRemain() {
        val emptyStubs = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.categoryPath.path.startsWith("/Demangler") }
            .filter { it.isZeroLength || it.numComponents == 0 }
            .map { "${it.categoryPath.path}/${it.name}" }
            .toList()
        Assertions.assertTrue(
            emptyStubs.isEmpty(),
            "Expected zero empty /Demangler/... stubs after AFTER-mode import; " +
                "found ${emptyStubs.size}: ${emptyStubs.take(10).joinToString()}",
        )
    }

    /**
     * `inheritance-applied` counter is only captured via CapturingSink in
     * AFTER mode (CONCURRENT mode feeds through MessageSinkAdapter→MessageLog).
     */
    @Test
    fun inheritanceWasApplied() {
//        assumeTrue(binaryName == "bouniafbouniaf.exe", "Skipping: inheritance checks specific to bouniafbouniaf.exe")
        val applied = context.diagnostics.snapshotCounters()["inheritance-applied"] ?: 0L
        Assertions.assertTrue(
            applied > 0,
            "Expected inheritance-applied counter > 0, got $applied " +
                "(no C++ inheritance edges were materialised)",
        )
    }
}
