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
import ghistabs.diagnose.CapturingSink
import ghistabs.diagnose.defaultContext
import ghistabs.harvest.Harvester
import ghistabs.importer.ImportContext
import ghistabs.importer.StaticContexts
import ghistabs.parse.*
import ghistabs.runTransaction
import kotlinx.serialization.ExperimentalSerializationApi
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
 *    Symptom seen on xapasmcsr.exe: many function names stay mangled
 *    (`_Z11RegToBinary12EnumRegToken`), presumably because the demangler runs
 *    later but skips symbols whose SourceType we've already promoted.
 *
 *  - [AFTER]: our analyzer is disabled in the analysis options before
 *    `startAnalysis` runs, so auto-analysis (demangler included) settles
 *    first. We then invoke StabsAnalyzer manually. Symptom seen here:
 *    `/Demangler/...` placeholder stubs created by Ghidra's demangler are
 *    sometimes not replaced (e.g. `/Demangler/XapArgRegInst`) — this was
 *    a DemanglerReplacer candidate-filtering bug, see DemanglerReplacer.
 */
enum class Mode { CONCURRENT, AFTER }

/**
 * Regression test harness for StabsAnalyzer on xapasmcsr.exe.
 *
 * Runs full analysis pipeline and validates counters against committed baseline.
 * Skips gracefully if fixture is absent (EULA-restricted, not in repo).
 */
@ParameterizedClass
@MethodSource("testParameters")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Execution(ExecutionMode.CONCURRENT)
@Tag("integration")
class StabsAnalyzerTests : AbstractGhidraHeadlessIntegrationTest() {
    companion object {
        val BINARIES = listOf("xapasmcsr.exe", "xmltest", "appquery.exe", "box2d_tests")

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
                contextual(IdInterface::class, ToStringSerializer())
                contextual(CategoryPath::class, ToStringSerializer())
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
                    program.runTransaction("disable-stabs-analyzer") {
                        options.setBoolean(ourName, false)
                    }
                    mgr.initializeOptions()
                    runAutoAnalysis(mgr, monitor)
                    program.runTransaction("stabs-analyze") {
                        StabsAnalyzer().run(context)
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
        program.runTransaction("auto-analyze") {
            mgr.startAnalysis(monitor)
            mgr.waitForAnalysis(null, monitor)
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
        assumeTrue(binaryName == "xapasmcsr.exe", "Skipping: baseline only exists for xapasmcsr.exe")
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
    fun xapArgInstNotUnderStdInclude() {
        val xapArgInst = program.dataTypeManager.allDataTypes
            .asSequence()
            .firstOrNull { it.name == "XapArgInst" }
        assumeTrue(xapArgInst != null, "Skipping: XapArgInst not found in DTM (stabs not processed)")
        Assertions.assertFalse(
            xapArgInst!!.categoryPath.path.startsWith("/std/"),
            "XapArgInst at ${xapArgInst.categoryPath.path} (expected non-/std/)",
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
     * because the bug is sporadic — observed on `XapArgRegLdStInst::Dump`
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
        assumeTrue(binaryName == "xapasmcsr.exe", "Skipping: CParser/Token_Type/EAsm specific to xapasmcsr.exe")
        // CParser, Token_Type and EAsm all canonicalise to the same TypeId because
        // gcc reuses local ids inside BINCL blocks per CU. Each must still reach the DTM.
        for (name in listOf("CParser", "Token_Type", "EAsm")) {
            val dt = program.dataTypeManager.allDataTypes.asSequence().firstOrNull { it.name == name }
            Assertions.assertNotNull(dt, "$name missing from DTM (shared BINCL canonical id collision)")
        }
    }

    @Test
    fun csymLexStreamPresent() {
        assumeTrue(binaryName == "xapasmcsr.exe", "Skipping: CSymLexStream specific to xapasmcsr.exe")
        val all = program.dataTypeManager.allDataTypes
            .asSequence()
            .filter { it.name == "CSymLexStream" }
            .map { "${it.categoryPath.path}/${it.name} (${it::class.simpleName}, len=${(it as? Structure)?.length})" }
            .toList()
        // CSymLexStream is defined inside STL headers (only entry points are template
        // instantiations) so it ends up under /std/<sorted-first-header>/ rather than
        // a project category. What matters is that it materialised as a non-empty
        // Structure that ClassBuilder can find via Attribution (i.e. the dedup +
        // sort-stable attribution agree on the same category).
        val best = all.firstOrNull { "(StructureDB" in it }
        Assertions.assertNotNull(best, "No CSymLexStream Structure in DTM. Got:\n${all.joinToString("\n")}")
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
    fun xapInstFirstComponentIsBase() {
        val xapInst = program.dataTypeManager.allDataTypes.asSequence()
            .firstOrNull { it.name == "XapInst" && it is Structure } as? Structure
        assumeTrue(xapInst != null, "Skipping: XapInst not found in DTM (stabs not processed)")
        assumeTrue(xapInst!!.numComponents > 0, "Skipping: XapInst has no components")
        val first = xapInst.getComponent(0)
        Assertions.assertEquals(
            0,
            first.offset,
            "XapInst first component should be at offset 0; got ${first.offset} (${first.fieldName})",
        )
        val dump = (0 until xapInst.numComponents).joinToString("\n") {
            val c = xapInst.getComponent(it)
            "  [${c.offset}] ${c.fieldName}: ${c.dataType.name} (${c.dataType::class.simpleName}, len=${c.length})"
        }
        val xis = program.dataTypeManager.allDataTypes.asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name == "XapInst" }
            .map { "${it.categoryPath.path} components=${it.numComponents} len=${it.length}" }
            .toList()
        Assertions.assertTrue(
            first.dataType is Structure,
            "XapInst first component '${first.fieldName}' should be a Structure (the parent class); " +
                "got ${first.dataType::class.simpleName} '${first.dataType.name}'\n" +
                "XapInst copies in DTM:\n${xis.joinToString("\n")}\n" +
                "First 5 components of selected XapInst:\n$dump",
        )
        val name = first.fieldName ?: ""
        Assertions.assertTrue(
            name.startsWith("_base_") && !name.startsWith("_base_unknown_"),
            "XapInst first component is '$name' (type=${first.dataType.name}); " +
                "expected _base_<parent-name> with a resolved parent class",
        )
        Assertions.assertEquals(
            "ExprInst",
            first.dataType.name,
            "XapInst's parent class should be ExprInst; got ${first.dataType.name}",
        )
    }

    /**
     * CLexStream extends basic_ifstream — verify the inheritance is
     * reflected in the layout. Two acceptable shapes:
     *  - A named `_base_basic_ifstream` (or `_vbase_…`) component at +0,
     *    if the base type resolved. Only happens when libstdc++'s stabs
     *    body is present in this binary (it isn't in xapasmcsr — only
     *    iosfwd's forward decl is emitted).
     *  - The struct's first own non-static field at offset > 0, with
     *    the base subobject reserved as bare Undefined1 (the explicit
     *    "don't pretend we know what's here" choice). This is the path
     *    xapasmcsr takes for CLexStream's basic_ifstream base.
     */
    @Test
    fun cLexStreamHasBaseField() {
        val cls = program.dataTypeManager.allDataTypes.asSequence()
            .firstOrNull { it.name == "CLexStream" && it is Structure } as? Structure
        assumeTrue(cls != null, "Skipping: CLexStream not found (stabs not processed)")
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
            "CLexStream: no _base_/_vbase_ component AND first own field at offset 0 — " +
                "no inheritance reflected at all",
        )
    }

    @Test
    fun unsignedInt() {
        assumeTrue(binaryName == "xapasmcsr.exe")
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

        Assertions.assertTrue(emptyCats.isEmpty(), "found ${emptyCats.values.sum()} empty structs in $emptyCats")
    }

    @Test
    fun demanglerStringReplaced() {
        assumeTrue(binaryName == "xapasmcsr.exe" || binaryName == "appquery.exe")
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
     * gcc/gdb encode void as a TypeAst with body `Ref(self.id)`. These show
     * up in method signatures as both the return type (every void-returning
     * ctor) and the trailing end-of-args sentinel. Without recognition
     * they'd surface as empty-Structure placeholders named `[<file>,N]`
     * polluting every demangled signature.
     *
     * The check: no DTM Structure should have a synthetic `[file,N]`-shaped
     * name, AND for xapasmcsr the specific path that prompted the discovery
     * (stdlib.h-derived `div_t` ctors) must not survive.
     */
    @Test
    fun voidSelfRefNotMaterialised() {
        // Enumerate every void self-Ref ast in the harvest (body = Ref(self.id)).
        // For each one assert no Structure was created at its category+name.
        val reader = ghistabs.parse.StabReader.fromProgram(program)!!
        val harvest = program.runTransaction("void-self-ref-harvest") {
            ghistabs.harvest.Harvester(TaskMonitor.DUMMY, context.sink, context.resolver).passA(reader.records)
        }
        val voidAsts = harvest.typeAsts.values.filter { ast ->
            val body = ast.body
            body is ghistabs.parse.TypeDecl.Ref && body.id == ast.id
        }
        assumeTrue(voidAsts.isNotEmpty(), "no void self-Refs in this fixture's harvest")

        val leaked = voidAsts.mapNotNull { ast ->
            // A void self-Ref must NOT materialise as a Structure under any
            // category bearing its synthetic ghidraName.
            program.dataTypeManager.allDataTypes.asSequence()
                .filterIsInstance<Structure>()
                .firstOrNull { it.name == ast.ghidraName }
                ?.pathName
        }
        Assertions.assertTrue(
            leaked.isEmpty(),
            "void self-Refs leaked as Structures: $leaked (out of ${voidAsts.size} void asts)",
        )

        // The original report (xapasmcsr): `(3,7)` in stdlib.h consumed by
        // Keywords.cpp. Explicit check so the assertion fires by exact name
        // if regressed.
        if (binaryName == "xapasmcsr.exe") {
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

    /**
     * Reproduces the GUI scenario: Ghidra's demangler eventually creates a
     * /Demangler/std/string Structure stub (e.g. when applying a mangled-symbol
     * function signature that references std::string), and we expect
     * DemanglerReplacer to substitute it with our /stabs/string typedef.
     *
     * The other `demanglerStringReplaced` test misses this because our headless
     * demangleMangledLabels invocation sets applySignature=false, suppressing
     * the placeholder creation that's the whole point of the test. Here we
     * create the stub by hand to exercise the post-import scenario.
     */
    @Test
    fun demanglerStringReplacedAfterStubInjection() {
        assumeTrue(binaryName == "xapasmcsr.exe" || binaryName == "appquery.exe")
        // Stub creation must happen inside a transaction.
        program.runTransaction("inject-demangler-stub") {
            val cat = program.dataTypeManager.createCategory(ghidra.program.model.data.CategoryPath("/Demangler/std"))
            cat.addDataType(
                ghidra.program.model.data.StructureDataType(
                    ghidra.program.model.data.CategoryPath("/Demangler/std"),
                    "string",
                    0,
                    program.dataTypeManager,
                ),
                ghidra.program.model.data.DataTypeConflictHandler.KEEP_HANDLER,
            )
        }
        val stubExists = program.dataTypeManager.getDataType(
            ghidra.program.model.data.CategoryPath("/Demangler/std"),
            "string",
        )
        Assertions.assertNotNull(stubExists, "precondition: injected stub should exist")

        // Re-run DemanglerReplacer.
        program.runTransaction("rerun-demangler-replacer") {
            ghistabs.importer.DemanglerReplacer(context).run()
        }

        val stubAfter = program.dataTypeManager.getDataType(
            ghidra.program.model.data.CategoryPath("/Demangler/std"),
            "string",
        )
        Assertions.assertNull(
            stubAfter,
            "/Demangler/std/string should have been replaced; still in DTM as $stubAfter",
        )
    }

    @Test
    fun atLeastOneVtableStructApplied() {
//        assumeTrue(binaryName == "xapasmcsr.exe", "Skipping: vtable layout checks specific to xapasmcsr.exe")
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
     * `DCInst` is a good probe class: polymorphic, several virtuals,
     * inherited slots — exercises all three gates.
     */
    @Test
    fun dcinstShiftSCompatibility() {
        val vftable = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name == "DCInst_vftable" }
            .maxByOrNull { it.numComponents }
        assumeTrue(vftable != null, "Skipping: DCInst_vftable not found")
        // Gate 1: CategoryPath under ClassDataTypes.
        Assertions.assertTrue(
            "ClassDataTypes" in vftable!!.categoryPath.path,
            "DCInst_vftable category '${vftable.categoryPath.path}' " +
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
            "DCInst_vftable: only $typedSlots/$totalSlots slots are typed " +
                "Pointer→FunctionDefinition. Slots: $slotTypeSummary",
        )
        // Gate 2: `vftable` symbol at the DTV address. Walk the symbol table
        // for `_ZTV6DCInst` (Itanium-mangled DTV symbol) and check siblings.
        val ztv = program.symbolTable.getSymbols("__ZTV6DCInst").firstOrNull()
        assumeTrue(ztv != null, "Skipping: DCInst not resolved")
        val sibs = program.symbolTable.getSymbols(ztv!!.address).toList()
        val sibSummary = sibs.map { "${it.parentNamespace.name}::${it.name}" }
        Assertions.assertTrue(
            sibs.any { "vftable" in it.name },
            "DCInst vtable address ${ztv.address} has no symbol containing 'vftable'; " +
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
            .filter { it.name == "DCInst_vtable" }
            .maxByOrNull { it.numComponents }
        assumeTrue(vtable != null, "Skipping: DCInst_vtable not found")
        val components = (0 until vtable!!.numComponents).map {
            val c = vtable.getComponent(it)
            "[${c.offset}] ${c.fieldName ?: "<unnamed>"}: ${c.dataType.name}"
        }
        val dups = program.dataTypeManager.allDataTypes
            .asSequence().filter { it.name == "DCInst_vtable" }
            .map { "${it.categoryPath.path}/${it.name} (len=${(it as Structure).length})" }
            .toList()
        val fieldNames = (0 until vtable.numComponents).map { vtable.getComponent(it).fieldName }
        Assertions.assertEquals(
            "offset_to_top",
            fieldNames.getOrNull(0),
            "Components:\n${components.joinToString("\n")}\n" +
                "DCInst_vtable copies in DTM:\n${dups.joinToString("\n")}",
        )
        Assertions.assertEquals("rtti", fieldNames.getOrNull(1))
        Assertions.assertEquals("vftable", fieldNames.getOrNull(2))
        // The function pointers live inside DCInst_vftable (what {vfptr} actually points to).
        val vmethods = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name == "DCInst_vftable" }
            .maxByOrNull { it.numComponents }
        Assertions.assertNotNull(vmethods, "DCInst_vftable not found")
        val virtuals = (0 until vmethods!!.numComponents).map {
            vmethods.getComponent(it).fieldName
        }.filterNotNull().toSet()
        // DCInst's own + inherited (Inst::Get* via ExprInst → XapInst → Inst chain).
        val expected = setOf(
            "GetInstType", "__comp_dtor", "__deleting_dtor",
            "Clone", "Dump", "GetSize", "PossibleFunctionReference",
            "GetOffset", "GetPrevOffset", "GetFullOffset", "GetPrevFullOffset",
        )
        val missing = expected - virtuals
        Assertions.assertTrue(
            missing.isEmpty(),
            "DCInst_vftable missing virtuals: $missing (have: $virtuals)",
        )
    }

    @Test
    fun atLeastOneRootClassHasVtableBackEdge() {
        assumeTrue(binaryName == "xapasmcsr.exe", "Skipping: vtable back-edge checks specific to xapasmcsr.exe")
        // At least one polymorphic class should directly contain a {vfptr} Pointer
        // pointing at its <Name>_vftable struct (the function pointer array — what
        // a real C++ vptr actually points at, vs. the full <Name>_vtable record that
        // also has the offset_to_top + rtti Itanium prefix).
        // Derived classes correctly *inherit* their vfptr via a `_base_<Parent>`
        // subobject so most won't carry the pointer directly; but the root of every
        // inheritance chain (e.g. Inst on xapasmcsr.exe) must, otherwise the
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
        // Enum is not required: xapasmcsr.exe may have no enum-typed globals.
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
        val harvest = program.runTransaction("stabs-harvest-dump") {
            harvester.passA(stabs.records)
        }

//        json.encodeToStream(harvest, harvestFile.outputStream())

        val classStructs = harvest.typeAsts.values
            .mapNotNull { it.asStruct() }
            .filter { (ast, body) -> body.kind == AggrKind.CLASS }
            .toList()

        val emptyStructs = harvest.typeAsts.values
            .mapNotNull { it.asStruct() }
            .filter { (ast, body) -> body.fields.isEmpty() && body.methods.isEmpty() }
            .toList()

        val resolver = ghistabs.harvest.TypeResolver(harvest.typeAsts)
        val baseTypes =
            harvest.typeAsts.values.filter { it.id.source is SourceFile.CUSource && !it.body.isXRefTarget }.toList()
        val different = baseTypes
            .groupBy { resolver.contentHash(it.body) }
            .mapKeys { (k, v) -> k to v.map { it.name }.toSet() }

        println("base types: ${different.mapValues { (_, v) -> v.size }}")
        for ((k, asts) in different) {
            val (hash, names) = k
            if (asts.size > 1 && names.contains(null)) {
                println("- $hash")
                for (ast in asts) {
                    val h = resolver.contentHash(ast.body)
                    println("       =>  $h ${ast.id} $ast")
                }
            }
        }
//        Assertions.assertFalse(doubleUnderscores.isEmpty(), "there should be double underscores")

//        val doubleUnderscores = harvest.typeAsts.values.filter { it.name.startsWith("__") }.toList()

//        Assertions.assertFalse(doubleUnderscores.isEmpty(), "there should be double underscores")

        Assertions.assertTrue(emptyStructs.isEmpty(), "there should not be structs with no field and no method")
//        Assertions.assertFalse(classStructs.isEmpty(), "there should be class structs")
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
        assumeTrue(binaryName == "xapasmcsr.exe", "Skipping: RegToBinary specific to xapasmcsr.exe")
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
        val knownNames = setOf("XapArgRegInst", "XapArgRegLdStInst", "DCInst")
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
//        assumeTrue(binaryName == "xapasmcsr.exe", "Skipping: inheritance checks specific to xapasmcsr.exe")
        val applied = context.diagnostics.snapshotCounters()["inheritance-applied"] ?: 0L
        Assertions.assertTrue(
            applied > 0,
            "Expected inheritance-applied counter > 0, got $applied " +
                "(no C++ inheritance edges were materialised)",
        )
    }

    /**
     * No class method should end up with two `this` parameters. The
     * historical regression (see ClassBuilder comment around the
     * `ghidraInjectsThis` decision) was the importer keeping the stab's
     * explicit leading `this` while Ghidra's `__thiscall` convention also
     * auto-injected one, producing
     *   `void XapArgRegLdStInst::Dump(XapArgRegLdStInst *this, ushort this, …)`
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
        Assertions.assertTrue(
            anon.isEmpty(),
            "Found ${anon.size} anonymous DTM types named after a GlobalTypeId:\n  - " +
                anon.joinToString("\n  - "),
        )
    }

    @Test
    fun mingwClassMethodsCarryThiscall() {
        assumeTrue(
            binaryName.endsWith(".exe"),
            "Skipping: __thiscall check only meaningful on mingw fixtures",
        )
        val classFuncs = program.functionManager.getFunctions(true).iterator().asSequence()
            .filter { it.parentNamespace is ghidra.program.model.listing.GhidraClass }
            .toList()
        val thiscalled = classFuncs.count { it.callingConventionName == "__thiscall" }
        Assertions.assertTrue(
            thiscalled > 0,
            "binary=$binaryName: ${classFuncs.size} class methods, none tagged __thiscall " +
                "(reparentMethod's setCallingConvention silently failed)",
        )
    }

    /**
     * CLexStream and CSymLexStream form a single-inheritance chain in
     * xapasmcsr (CSymLexStream extends CLexStream extends basic_ifstream).
     * gcc's stab is internally inconsistent on both — `s328` / `s416`
     * declare more bytes than the layout actually describes (CLexStream's
     * last own field Tok ends at 192; CSymLexStream's last own field
     * RecoverySet ends at 276). The placeholder-truncate fix uses
     * "last described byte" as the size, which (a) removes the trailing
     * unexplained padding and (b) makes CLexStream's size match what
     * CSymLexStream's CU expects from its base — so the base placement
     * fits cleanly without overwrite or synthesis.
     *
     * This also requires the truncate to happen at placeholder-creation
     * time (not later), so the size is consistent across pre-seed and
     * the materialise-winner loop regardless of order: CSymLexStream's
     * base loop sees CLexStream's already-truncated placeholder.
     */
    @Test
    fun cLexStreamAndCSymLexStreamTruncated() {
        assumeTrue(binaryName == "xapasmcsr.exe", "Skipping: CLexStream chain is xapasmcsr-specific")

        fun findStruct(name: String): Structure = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .firstOrNull { it.name == name }
            ?: throw AssertionError("Structure '$name' not in DTM")

        // CLexStream: truncate to its last own field end. Tok at +168 size 24 → 192.
        val clex = findStruct("CLexStream")
        Assertions.assertEquals(
            192,
            clex.length,
            "CLexStream should be truncated to 192 (Tok ends at 168+24); got ${clex.length}",
        )
        val clexFields = clex.components.associateBy { it.fieldName ?: "" }
        Assertions.assertEquals(112, clexFields["LineNo"]?.offset, "LineNo expected at +112")
        Assertions.assertEquals(168, clexFields["Tok"]?.offset, "Tok expected at +168")
        Assertions.assertEquals(24, clexFields["Tok"]?.length, "Tok expected to span 24 bytes")

        // CSymLexStream: own fields end at RecoverySet+40 = 276. Truncate target = 276.
        val csym = findStruct("CSymLexStream")
        Assertions.assertEquals(
            276,
            csym.length,
            "CSymLexStream should be truncated to 276 (RecoverySet ends at 236+40); got ${csym.length}",
        )

        // CSymLexStream's base at +0 must be CLexStream itself (resolved, not
        // a synthesised placeholder). That's the cascade: CLexStream's
        // truncate-to-192 made it fit exactly in CSymLexStream's 192-byte gap.
        val csymFields = csym.components.associateBy { it.fieldName ?: "" }
        val baseField = csymFields["_base_CLexStream"]
        Assertions.assertNotNull(
            baseField,
            "_base_CLexStream missing from CSymLexStream; components: ${csymFields.keys}",
        )
        Assertions.assertEquals(0, baseField!!.offset, "_base_CLexStream expected at +0")
        Assertions.assertEquals(192, baseField.length, "_base_CLexStream expected to span 192 bytes")
        Assertions.assertSame(
            clex,
            baseField.dataType,
            "_base_CLexStream's dataType should be the same CLexStream Structure",
        )

        Assertions.assertEquals(192, csymFields["CurrentTok"]?.offset, "CurrentTok expected at +192")
        Assertions.assertEquals(236, csymFields["RecoverySet"]?.offset, "RecoverySet expected at +236")
        Assertions.assertEquals(40, csymFields["RecoverySet"]?.length, "RecoverySet expected to span 40 bytes")
    }
}
