# ghidra-stabs Phase 6: Entry points & integration

**Goal:** Wire the importer to Ghidra's analyzer + plugin lifecycle. Auto-runs once per program (gated by a persistent done-flag), re-runnable via a `Tools > Stabs > Re-import` menu action. Freeze count assertions against `xapasmcsr.exe` and produce an installable `.zip`.

**Architecture:** Two entry points, one core. `StabsAnalyzer` extends `AbstractAnalyzer` and is auto-discovered by Ghidra; it gates execution on `STABS_DONE_OPTION`. `StabsPlugin` is a `ProgramPlugin` that adds a single `DockingAction` to the Tools menu; the action clears the done-flag and schedules a one-time analysis via `AutoAnalysisManager.scheduleOneTimeAnalysis`. Both invoke the same `StabsImporter.run`.

**Tech Stack:** Kotlin 2.3.21, Java 21 (for `StabsPlugin.java`), Ghidra extension SDK, JUnit 5 + `ProgramBuilder` for Ring-2/Ring-3 tests.

**Scope:** Phase 6 of 6.

**Codebase verified:** 2026-05-07.

**Codebase verification findings:**
- ✓ Skeleton's `StabsAnalyzer.kt` and `StabsPlugin.java` are present with stub bodies — must be rewritten in this phase. `StabsLoader.kt` and `StabsExporter.java` were deleted in Phase 1.
- ✓ `AbstractAnalyzer` (`Ghidra/Features/Base/src/main/java/ghidra/app/services/AbstractAnalyzer.java`): hooks are `getDefaultEnablement(Program)`, `canAnalyze(Program)`, `added(Program, AddressSetView, TaskMonitor, MessageLog): boolean`, `registerOptions(Options, Program)`, `optionsChanged(Options, Program)`. `setSupportsOneTimeAnalysis()` allows the analyzer to be triggered out-of-cycle.
- ✓ `AnalysisPriority`: `LATER` is `100` per design; alternatives include `FIRST_PASS`, `FORMAT_ANALYSIS_PRIORITY`, `BLOCK_ANALYSIS_PRIORITY` (lower numbers run earlier). LATER ensures Ghidra's loaders/symbol-table populating analyzers finish first.
- ✓ `AutoAnalysisManager.scheduleOneTimeAnalysis(Analyzer, AddressSetView)` exists at line 226 of `AutoAnalysisManager.java`. Caller pattern: `AutoAnalysisManager.getAnalysisManager(program).scheduleOneTimeAnalysis(myAnalyzer, program.memory)`.
- ✓ `Program.PROGRAM_INFO` is the canonical option-group key for "import metadata" flags. We add `STABS_DONE_OPTION = "Stabs Imported"`.
- ✓ `ProgramPlugin` + `DockingAction` pattern: see `Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/...` — concrete examples pervasive (e.g. `ProgramTreePlugin`).
- ✓ `extension.properties` already has the templating tokens `@extname@` / `@extversion@` — `buildExtension.gradle` substitutes these. We add `description`, `author`, `createdOn` values.
- ✓ Skeleton is registered with category `PluginCategoryNames.EXAMPLES` and `ExamplesPluginPackage.NAME` — must change to a real category (`ANALYSIS` is the right slot for a stabs analyzer's plugin sibling).

**External dependency findings:**
- 📖 **`gradle distributeExtension`:** the skeleton's task definition is `dependsOn(":buildExtension")` (Gradle 9 colon-prefix for the same-project task). `buildExtension` is contributed by `support/buildExtension.gradle` from `$GHIDRA_INSTALL_DIR`. Output goes to `dist/<ghidra-version>_<date>_<extname>.zip`. Confirmed against ADK4.0.1 / 12.0.4 install at `/home/riton/git/bouse/ghidra-stabs/dist/ghidra_12.0.4_DEV_20260505_ghidra-stabs.zip` (already produced once during skeleton scaffolding).
- 📖 **Ghidra extension layout:** the zip must contain `extension.properties`, `Module.manifest`, `lib/<jars>`, `data/`, `ghidra_scripts/`, `os/<platform>/`. `buildExtension.gradle` assembles this.
- 📖 **CSR ADK redistribution:** `xapasmcsr.exe` is a CSR-proprietary binary distributed under the ADK EULA (closed-source). Copying it into the public ghidra-stabs repo for tests requires user confirmation. Default: do NOT commit; the integration test uses `assumeTrue(file.exists())` to skip cleanly when absent.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### ghidra-stabs.AC1: Container reading and analyzer lifecycle

- **ghidra-stabs.AC1.3 Success:** Auto-analyzer runs on first import of a program containing `.stab` + `.stabstr`; sets `STABS_DONE_OPTION` to `true`; second `startAnalysis` is a no-op.
- **ghidra-stabs.AC1.4 Success:** `Tools > Stabs > Re-import` clears the done-flag, re-runs the importer, and produces an idempotent DTM/symbol state on a fully-imported program.
- **ghidra-stabs.AC1.5 Failure:** A program with no `.stab` block yields `canAnalyze == false`; the analyzer never runs and the menu action is disabled.

### ghidra-stabs.AC3: Type resolution

- **ghidra-stabs.AC3.5 Success:** On `xapasmcsr.exe`, ≥ 80 "interesting" project typenames (per the Phase 1 stats output's `INTERESTING project typenames` list) are present in the DTM after import.

### ghidra-stabs.AC4: Symbol application

- **ghidra-stabs.AC4.6 Success:** On `xapasmcsr.exe`, ≥ 470 of the 990 `N_FUN` records have named parameters; ≥ 92 have locals; the remainder are bookmark-free (compiler stubs without param info).

### ghidra-stabs.AC6: Error handling, idempotence, packaging

- **ghidra-stabs.AC6.4 Success:** Re-running the importer (auto-analyze with flag cleared, or via the menu action) on a fully-imported program produces no duplicate types, no duplicate labels, and no namespace duplication; the resulting DTM/symbol state is byte-identical to the first run (modulo bookmarks).
- **ghidra-stabs.AC6.5 Success:** `gradle distributeExtension` produces a `.zip` in `dist/` that installs into Ghidra 12.0.4 without errors and the analyzer appears in the `Auto Analysis` dialog.

---

## Implementation Tasks

<!-- START_TASK_1 -->
### Task 1: `StabsAnalyzer` — replace skeleton stub with real analyzer

**Files:**
- Modify: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/StabsAnalyzer.kt` (full rewrite)

**Implementation:**

```kotlin
package ghistabs

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.framework.options.Options
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.importer.ImportContext
import ghistabs.importer.StabsImporter
import ghistabs.importer.StabsOptions

// AnalyzerType.BYTE_ANALYZER chosen because we operate on raw `.stab` / `.stabstr`
// section bytes, not on already-disassembled code (so INSTRUCTION_ANALYZER is wrong)
// or function-level analysis (FUNCTION_ANALYZER runs per-function — we need a one-shot
// program-wide pass). Precedent: GnuDemanglerAnalyzer (the closest analog — also
// post-loader, also crosses the symbol table) uses BYTE_ANALYZER.
class StabsAnalyzer : AbstractAnalyzer(
    "Stabs Importer",
    "Imports STABS debug info (.stab/.stabstr) — types, function signatures, locals, C++ classes, vtables.",
    AnalyzerType.BYTE_ANALYZER,
) {
    init {
        priority = AnalysisPriority.LATER
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun getDefaultEnablement(program: Program?): Boolean = true

    override fun canAnalyze(program: Program?): Boolean {
        if (program == null) return false
        if (isStabsDone(program)) return false
        val mem = program.memory
        return mem.getBlock(".stab") != null && mem.getBlock(".stabstr") != null
    }

    override fun registerOptions(options: Options, program: Program?) {
        options.registerOption(
            OPT_PLATE_COMMENTS, true, null,
            "Apply plate comments at lexical scopes when LBRAC/RBRAC info is present.",
        )
        options.registerOption(
            OPT_VTABLES, true, null,
            "Synthesise <Class>_vtable structs and apply at _ZTV addresses.",
        )
    }

    override fun added(program: Program?, set: AddressSetView?, monitor: TaskMonitor?, log: MessageLog?): Boolean {
        program ?: return false
        log ?: return false
        monitor ?: return false
        if (isStabsDone(program)) return true   // idempotent re-trigger; treat as success.

        val opts = program.getOptions(Program.ANALYSIS_PROPERTIES).getOptions(name)
        val stabsOptions = StabsOptions(
            applyPlateComments = opts.getBoolean(OPT_PLATE_COMMENTS, true),
            applyVtables = opts.getBoolean(OPT_VTABLES, true),
        )
        val ctx = ImportContext(program, log, monitor, stabsOptions)
        val result = StabsImporter(ctx).run()
        log.appendMsg("[Stabs] import complete: $result")
        markStabsDone(program, true)
        return true
    }

    companion object {
        const val STABS_DONE_OPTION = "Stabs Imported"
        const val OPT_PLATE_COMMENTS = "Apply scope plate comments"
        const val OPT_VTABLES = "Synthesise vtable structs"

        fun isStabsDone(program: Program): Boolean =
            program.getOptions(Program.PROGRAM_INFO).getBoolean(STABS_DONE_OPTION, false)

        fun markStabsDone(program: Program, value: Boolean) {
            val tx = program.startTransaction("Stabs: set done flag")
            try {
                program.getOptions(Program.PROGRAM_INFO).setBoolean(STABS_DONE_OPTION, value)
            } finally {
                program.endTransaction(tx, true)
            }
        }
    }
}
```

**Step: Compile**

```bash
./gradlew compileKotlin
```

**Step: Commit**

```bash
git add src/main/kotlin/ghistabs/StabsAnalyzer.kt
git commit -m "feat(analyzer): wire StabsAnalyzer to importer with done-flag gate"
```

**Verifies:** Implementation-side of `ghidra-stabs.AC1.3`, `ghidra-stabs.AC1.5`.
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: `StabsPlugin` — replace skeleton stub with `Tools > Stabs > Re-import` action

**Files:**
- Modify: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/StabsPlugin.java` (full rewrite)

**Implementation:**

```java
package ghistabs;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.AnalysisOptionsDialog;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = ghidra.framework.main.AnalyzerPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Re-run the STABS importer on the current program.",
    description = "Adds a 'Tools > Stabs > Re-import' action that clears the persistent done-flag and re-runs the StabsAnalyzer."
)
public class StabsPlugin extends ProgramPlugin {

    public StabsPlugin(PluginTool tool) {
        super(tool);
        DockingAction reimport = new DockingAction("Stabs Re-import", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                Program program = getCurrentProgram();
                if (program == null) {
                    Msg.showInfo(getClass(), null, "Stabs Re-import", "No program is open.");
                    return;
                }
                int tx = program.startTransaction("Stabs: clear done flag (re-import)");
                try {
                    program.getOptions(Program.PROGRAM_INFO)
                        .setBoolean(StabsAnalyzer.STABS_DONE_OPTION, false);
                } finally {
                    program.endTransaction(tx, true);
                }
                AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
                StabsAnalyzer analyzer = new StabsAnalyzer();
                mgr.scheduleOneTimeAnalysis(analyzer, program.getMemory());
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                Program p = getCurrentProgram();
                if (p == null) return false;
                return p.getMemory().getBlock(".stab") != null
                    && p.getMemory().getBlock(".stabstr") != null;
            }
        };
        reimport.setMenuBarData(new MenuData(new String[] { "&Tools", "Stabs", "&Re-import" }, null, "Stabs"));
        reimport.setEnabled(true);
        tool.addAction(reimport);
    }
}
```

**Kotlin `companion object` access from Java.** The Java code above uses bare `StabsAnalyzer.STABS_DONE_OPTION`. For that to compile, the companion's constant must be marked `@JvmField`. Update the `StabsAnalyzer.kt` companion to:

```kotlin
companion object {
    @JvmField val STABS_DONE_OPTION: String = "Stabs Imported"
    @JvmField val OPT_PLATE_COMMENTS: String = "Apply scope plate comments"
    @JvmField val OPT_VTABLES: String = "Synthesise vtable structs"

    @JvmStatic fun isStabsDone(program: Program): Boolean = ...
    @JvmStatic fun markStabsDone(program: Program, value: Boolean) { ... }
}
```

`@JvmField` exposes the constant as a real `public static final String` field; `@JvmStatic` lifts companion methods to static methods. With these annotations the Java side is `StabsAnalyzer.STABS_DONE_OPTION` (field access) and `StabsAnalyzer.isStabsDone(program)` (static-method call) — no `Companion.get…()` indirection. Update Task 1's `StabsAnalyzer.kt` to match.

**Step: Compile**

```bash
./gradlew build
```

**Step: Commit**

```bash
git add src/main/kotlin/ghistabs/StabsPlugin.java src/main/kotlin/ghistabs/StabsAnalyzer.kt
git commit -m "feat(plugin): Tools > Stabs > Re-import action"
```

**Verifies:** Implementation-side of `ghidra-stabs.AC1.4`.
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: `extension.properties` — author, description, created-on

**Files:**
- Modify: `/home/riton/git/bouse/ghidra-stabs/extension.properties`

**Implementation:**

Replace contents with:

```properties
name=@extname@
description=Imports STABS debug info (.stab/.stabstr) into Ghidra: types, function signatures, locals, C++ classes, vtables. Targets PE/ELF binaries produced by Cygwin gcc 3.4.4.
author=Henri Chain <unexpectedtrampoline@gmail.com>
createdOn=2026-05-06
version=@extversion@
```

(`@extname@` and `@extversion@` are template tokens substituted by `buildExtension.gradle`.)

**Step: Commit**

```bash
git add extension.properties
git commit -m "chore(meta): populate extension.properties"
```

**Verifies:** Partial `ghidra-stabs.AC6.5`.
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Lifecycle test — `canAnalyze`, done-flag idempotence (Ring-2)

**Files:**
- Create: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs/StabsAnalyzerLifecycleTest.kt`

**Setup:** Use `ProgramBuilder` to construct an in-memory program. For the no-stabs case, build with no `.stab`/`.stabstr` blocks. For the with-stabs case, manually create the blocks with synthetic byte content (use Phase 1's fixture builder).

**Tests must verify:**

- **`ghidra-stabs.AC1.5`**: A program with no `.stab` block ⇒ `analyzer.canAnalyze(program) == false`.
- **`ghidra-stabs.AC1.3`** (first run): A program with `.stab` + `.stabstr` ⇒ `canAnalyze == true`. After `analyzer.added(...)`, `STABS_DONE_OPTION == true` AND a second call to `canAnalyze` returns `false`.
- **`ghidra-stabs.AC1.4`** (re-import): Clear the done-flag manually (simulating the plugin action). `canAnalyze` returns `true` again. Run `added`. Compare DTM state before/after second run: type count is unchanged (no duplicates).

**Step: Run, commit**

```bash
./gradlew test --tests 'ghistabs.StabsAnalyzerLifecycleTest'
git add src/test/kotlin/ghistabs/StabsAnalyzerLifecycleTest.kt
git commit -m "test(analyzer): canAnalyze gate, done-flag idempotence"
```

**Verifies:** `ghidra-stabs.AC1.3`, `ghidra-stabs.AC1.4`, `ghidra-stabs.AC1.5`.
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Idempotence test — re-run produces byte-identical DTM/symbol state

**Files:**
- Create: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs/IdempotenceTest.kt`

**Implementation:**

Build a program with a non-trivial synthetic `.stab` payload (a struct, a function with a parameter, a global, a class with one virtual method). Run `StabsImporter.run()` twice.

Snapshot helpers (Ring-2 utilities):
- `dtmSnapshot(dtm: DataTypeManager): String` → join `getAllDataTypes().map { it.pathName }.sorted()`.
- `symbolSnapshot(symtab: SymbolTable): String` → join `getAllSymbols(true).map { "${it.address}:${it.name}:${it.source}" }.sorted()`.

**Tests must verify (`ghidra-stabs.AC6.4`):**

- After two runs (with done-flag manually cleared between them), `dtmSnapshot` is identical.
- `symbolSnapshot` is identical (modulo any auto-applied addresses with timestamp metadata — assert NOT equal only because of a timestamp would be a bug; we treat the assertion as exact equality and let any drift surface).
- Bookmark count for category `Stabs:vtable` is the same before/after.

**Step: Run, commit**

```bash
./gradlew test --tests 'ghistabs.IdempotenceTest'
git add src/test/kotlin/ghistabs/IdempotenceTest.kt
git commit -m "test(importer): idempotence (DTM and symbol state byte-identical across re-runs)"
```

**Verifies:** `ghidra-stabs.AC6.4`.
<!-- END_TASK_5 -->

<!-- START_TASK_6 -->
### Task 6: Real-binary integration test — `xapasmcsr.exe` count thresholds (Ring-3)

**Files:**
- Create: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs/XapasmcsrIntegrationTest.kt`

**Setup:**
- Fixture path: `/home/riton/git/bouse/ghidra-stabs/src/test/resources/binaries/xapasmcsr.exe`. Test uses `Assumptions.assumeTrue(file.exists())` so absent fixture skips cleanly.
- Use `ProgramBuilder` or directly `MessageLog` + Ghidra's PE loader (`PeLoader`) to import the binary into a fresh `Program`.
- The test is tagged `@Tag("integration")` so it can be excluded from the fast `./gradlew test` run and included via `./gradlew integrationTest`.

Add to `build.gradle.kts`:

```kotlin
val integrationTest = tasks.register<Test>("integrationTest") {
    description = "Real-binary tests against ADK fixtures"
    group = "verification"
    useJUnitPlatform { includeTags("integration") }
    testClassesDirs = sourceSets["test"].output.classesDirs
    classpath = sourceSets["test"].runtimeClasspath
    shouldRunAfter("test")
}
tasks.test { useJUnitPlatform { excludeTags("integration") } }
```

**Tests must verify:**

- **`ghidra-stabs.AC1.3`** + **`ghidra-stabs.AC1.4`** (lifecycle on real binary): After auto-analyzer runs, `STABS_DONE_OPTION == true`. Re-trigger via `AutoAnalysisManager.scheduleOneTimeAnalysis(analyzer, program.memory)` after clearing the flag — completes without throwing.
- **`ghidra-stabs.AC3.5`** (≥ 80 interesting typenames): the design's "INTERESTING project typenames" list isn't enumerated — the implementor harvests it once via `parse_image/stabs_stats.py`'s output. Save the list at `src/test/resources/corpus/xapasmcsr-interesting-typenames.txt` (one name per line). Test reads file, asserts ≥ 80 of those names appear in `dtm.getAllDataTypes()` (matched by `name`, ignoring `CategoryPath`).
- **`ghidra-stabs.AC4.6`** (function/param/local counts): After import, count `program.functionManager.getFunctions(true)` whose `parameterCount > 0` and whose first parameter's source is `IMPORTED`. Assert ≥ 470. Count functions with at least one local variable; assert ≥ 92.
- **`ghidra-stabs.AC5`** (≥ 50 GhidraClass namespaces): Count `program.symbolTable.getClassNamespaces()`. Assert ≥ 50.

**Step: Run, commit**

```bash
./gradlew integrationTest --tests 'ghistabs.XapasmcsrIntegrationTest'
# (skips if fixture absent)
git add src/test/kotlin/ghistabs/XapasmcsrIntegrationTest.kt build.gradle.kts \
        src/test/resources/corpus/.gitkeep
git commit -m "test(integration): xapasmcsr.exe count thresholds"
```

**Note on fixture commit:** `xapasmcsr.exe` itself is NOT committed (CSR ADK EULA). The implementor must surface this to the user before deciding. The `.gitkeep` is committed so the directory exists; the binary is fetched manually per developer.

**Verifies:** `ghidra-stabs.AC3.5`, `ghidra-stabs.AC4.6`, `ghidra-stabs.AC5` (count assertion), `ghidra-stabs.AC1.3` + `AC1.4` on real binary.
<!-- END_TASK_6 -->

<!-- START_TASK_7 -->
### Task 7: Distribution build — verify `gradle distributeExtension` produces an installable `.zip`

**Files:**
- (No new files — verification step.)

**Implementation:**

```bash
cd /home/riton/git/bouse/ghidra-stabs
./gradlew clean distributeExtension
```

Expected output: `dist/ghidra_<ghidra-version>_<date>_ghidra-stabs.zip` exists and unzips to a directory containing `extension.properties`, `Module.manifest`, `lib/ghidra-stabs.jar`, `os/`, `ghidra_scripts/`.

Smoke-install procedure (manual, not automated):
1. Open Ghidra 12.0.4.
2. `File > Install Extensions… > +` (add zip).
3. Select `dist/ghidra_12.0.4_*_ghidra-stabs.zip`.
4. Restart Ghidra.
5. Open any program. `Analysis > Auto Analyze…` should list "Stabs Importer" in the analyzer list.
6. `Tools` menu should contain `Stabs > Re-import`.

If steps 2–6 succeed: AC6.5 satisfied.

**Step: Tag the verification commit**

```bash
git tag -a v0.1.0 -m "ghidra-stabs v0.1.0 — initial integration"
```

(Tag only — no separate commit needed; the prior commits comprise the release.)

**Verifies:** `ghidra-stabs.AC6.5`.
<!-- END_TASK_7 -->

---

## Phase Done When

- [ ] `StabsAnalyzer.kt` rewritten — runs only when `.stab`/`.stabstr` present AND done-flag false; sets done-flag on success; supports one-time analysis.
- [ ] `StabsPlugin.java` rewritten — adds `Tools > Stabs > Re-import` action that clears flag + schedules one-time analysis.
- [ ] `extension.properties` populated with author/description/createdOn.
- [ ] `StabsAnalyzerLifecycleTest`, `IdempotenceTest` green.
- [ ] `XapasmcsrIntegrationTest` runs in `integrationTest` task; passes when fixture present (skips otherwise) with ≥ 80 typenames, ≥ 470 functions w/ named params, ≥ 92 with locals, ≥ 50 classes.
- [ ] `./gradlew distributeExtension` produces a `.zip` in `dist/`. Manual install into Ghidra 12.0.4 works.
- [ ] `v0.1.0` tag.

## Open Questions for User

- **Commit `xapasmcsr.exe` to the repo?** It's a CSR ADK proprietary binary; redistribution status unclear. Default plan: do not commit, fixture path is `.gitignore`d, integration test skips when absent. Need explicit confirmation.
- **Where does the "INTERESTING project typenames" list come from?** Phase 1 stats output is the design's reference but the list isn't pinned in the design body. Implementor extracts it once via pyghidra and commits to `src/test/resources/corpus/xapasmcsr-interesting-typenames.txt`. OK?
- **Plugin category — `ANALYSIS` is the natural fit; confirm.** The skeleton uses `EXAMPLES`. Switch to `ANALYSIS` and `AnalyzerPluginPackage.NAME` (which is what other analyzer-companion plugins use).
