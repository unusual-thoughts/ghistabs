# ghidra-stabs Phase 1: Foundation & container

**Goal:** Project hygiene, byte-level reading of `.stab`/`.stabstr` sections, and address-resolution facade that tolerates stripped binaries.

**Architecture:** Pure Kotlin walkers over `MemoryBlock` bytes producing immutable `StabRecord` values plus an `AddressResolver` facade. Zero side effects on `Program` other than creating `IMPORTED` labels at stab-derived addresses. FCIS: this layer is the read-only foundation for later passes.

**Tech Stack:** Kotlin 2.3.21, JDK 21, Gradle 9.3.0, Ghidra 12.0.4 extension SDK, JUnit 5.

**Scope:** Phase 1 of 6.

**Codebase verified:** 2026-05-07.

**Codebase verification findings:**
- ✓ Skeleton present at `/home/riton/git/bouse/ghidra-stabs/` (own git repo, branch `ghidra-stabs`, initial commit `eefe2bc`).
- ✓ `src/main/kotlin/ghistabs/StabsAnalyzer.kt`, `StabsLoader.kt`, `StabsExporter.java`, `StabsPlugin.java` — all are stock skeleton stubs with placeholder text ("My Analyzer", "Hello!").
- ✓ `Module.manifest` is empty (zero bytes).
- ✓ `build.gradle.kts` applies `$GHIDRA_INSTALL_DIR/support/buildExtension.gradle` and registers a `distributeExtension` task. JVM toolchain 21, Kotlin stdlib only.
- ✓ `extension.properties` is templated (`@extname@`, `@extversion@`) — Gradle fills in.
- ✗ No `.gitignore` — must add (build/, .gradle/, .idea/, .vscode/, .kotlin/, dist/, lib/ binary jars).
- ✗ No `src/test/kotlin/` directory — must create.
- ✗ No JUnit dependency in `build.gradle.kts` — must add (`testImplementation`).
- ✓ Ghidra source classes referenced by design exist: `AbstractAnalyzer` (`Ghidra/Features/Base/src/main/java/ghidra/app/services/AbstractAnalyzer.java`), `AutoAnalysisManager` (`scheduleOneTimeAnalysis(Analyzer, AddressSetView)` at line 226), `ClassUtils.VFPTR`, `NamespaceUtils.convertNamespaceToClass`, `GnuDemanglerAnalyzer` (reference for analyzer wiring).
- ✓ `parse_image/stabs_stats.py` exists (533 lines) and defines the `STAB_TYPES` mnemonic table plus `TYPES_WITH_CONTINUATION = {0x20, 0x24, 0x26, 0x28, 0x40, 0x80, 0xA0}` we mirror in Kotlin.
- ✓ Real corpus binary `xapasmcsr.exe` exists at `~/.wine/drive_c/ADK2.5.1/tools/lib/gcc-lib/xap-local-xap/3.3.3/xapasmcsr.exe` (and two other ADK paths).

**External dependency findings:**
- 📖 STABS wire format: 12-byte record `(uint32 n_strx, uint8 n_type, uint8 n_other, uint16 n_desc, uint32 n_value)`. PE/COFF emits the section as `.stab` with paired `.stabstr` (string table). Per-CU offset trick: a leading record with `n_type == N_UNDF (0x00)` carries `n_value` = size of that CU's slice of `.stabstr`; the importer maintains `cu_off` and `cu_size` cursors and indexes strings as `stabstr[cu_off + n_strx]`.
- 📖 `\`-continuation: when the descriptor string of a symbol-bearing record (types in `TYPES_WITH_CONTINUATION`) ends in `\`, drop that backslash and concatenate the next record's string. Continuation records carry the same `n_type` and 0 in their non-string fields. Reassembled string is logically a single record; only the first record's `n_other`/`n_desc`/`n_value` matter.
- 📖 Endianness: `.stab` records are little-endian on x86 PE/ELF (matches Cygwin gcc 3.4.4 output). On big-endian targets they would be big-endian, but those are out of scope per design.
- 📖 Ghidra `MemoryBlock` API: `program.memory.getBlock(name: String): MemoryBlock?`; `block.getBytes(start: Address, dest: ByteArray, offset: Int, length: Int): Int`; `block.size: Long`; `block.start: Address`. Use `ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)` for parsing.
- 📖 Ghidra `SymbolTable` API: `symtab.getSymbols(name: String): Array<Symbol>`; `symtab.createLabel(addr: Address, name: String, source: SourceType): Symbol`. Use `SourceType.IMPORTED` for stab-derived labels (per design + memory `feedback_prefer_ghidra_api.md`).

---

## Acceptance Criteria Coverage

This phase implements and tests:

### ghidra-stabs.AC1: Container reading and analyzer lifecycle

- **ghidra-stabs.AC1.1 Success:** Reader recovers all `(stabSize / 12)` 12-byte records from a fixture's `.stab` section, with names correctly assembled across `\`-continuation runs.
- **ghidra-stabs.AC1.2 Success:** Reader correctly applies the per-CU stabstr offset trick (`N_UNDF` header advances `cu_off += cu_size; cu_size = n_value`); strings from later CUs decode without garbling.

### ghidra-stabs.AC6: Error handling, idempotence, and stripped-binary tolerance

- **ghidra-stabs.AC6.1 Success:** A binary with stabs but missing COFF/ELF symbol tables (stripped) still receives `IMPORTED` labels at every `N_FUN` / `N_STSYM` / `N_LCSYM` address; `N_GSYM` and class-method linkages produce log entries (no symbol to bind to).

(Phase 1 partially addresses AC6.1 — only the "stab-derived addresses produce `IMPORTED` labels" half via `AddressResolver.recordFromStab`. The full record-kind dispatch is wired in Phase 4.)

---

## Implementation Tasks

<!-- START_TASK_1 -->
### Task 1: Project hygiene — delete stub files, add .gitignore, JUnit deps

**Files:**
- Delete: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/StabsLoader.kt`
- Delete: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/StabsExporter.java`
- Modify: `/home/riton/git/bouse/ghidra-stabs/Module.manifest` (currently empty — leave empty; the design says no module-manifest entries for the stubs need removing because none exist)
- Create: `/home/riton/git/bouse/ghidra-stabs/.gitignore`
- Modify: `/home/riton/git/bouse/ghidra-stabs/build.gradle.kts` (add JUnit 5 test deps and `useJUnitPlatform()`)
- Create: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/.gitkeep` (so the directory exists in git)

**Step 1: Delete the loader/exporter stubs**

```bash
cd /home/riton/git/bouse/ghidra-stabs
rm src/main/kotlin/ghistabs/StabsLoader.kt src/main/kotlin/ghistabs/StabsExporter.java
```

(The skeleton's `StabsAnalyzer.kt` and `StabsPlugin.java` are kept and rewritten in Phase 6.)

**Step 2: Write `.gitignore`**

```
# Build outputs
build/
dist/

# Gradle
.gradle/
.kotlin/

# Vendored runtime jars (downloaded by buildExtension.gradle)
lib/*.jar

# IDE
.idea/
.vscode/
*.iml

# OS
.DS_Store
Thumbs.db
```

**Step 3: Modify `build.gradle.kts` — add JUnit 5 + test toolchain block**

Replace the entire file contents with:

```kotlin
plugins {
    id("org.jetbrains.kotlin.jvm") version "2.3.21"
}

dependencies {
    implementation(kotlin("stdlib"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

repositories {
    mavenCentral()
}

kotlin {
    jvmToolchain(21)
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

val ghidraInstallDir =
    System.getenv("GHIDRA_INSTALL_DIR") ?: project.properties["GHIDRA_INSTALL_DIR"]?.toString() ?: "/opt/ghidra"

apply(from = File(ghidraInstallDir).canonicalPath + "/support/buildExtension.gradle")

tasks.register("distributeExtension") {
    group = "Ghidra"
    dependsOn(":buildExtension")
}

// Exclude additional files from the built extension
// Ex: buildExtension.exclude(".idea/**")
```

**Step 4: Create test source root**

```bash
mkdir -p /home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs
touch /home/riton/git/bouse/ghidra-stabs/src/test/kotlin/.gitkeep
```

**Step 5: Verify operationally**

```bash
cd /home/riton/git/bouse/ghidra-stabs
./gradlew build
```

Expected: build succeeds (no compilation errors after stub removal). The Ghidra extension build will continue to work via `buildExtension.gradle`.

```bash
./gradlew test
```

Expected: `BUILD SUCCESSFUL — 0 tests, 0 failures` (no tests written yet).

**Step 6: Commit**

```bash
cd /home/riton/git/bouse/ghidra-stabs
git add -A
git commit -m "chore: project hygiene (gitignore, junit deps, drop stub files)"
```

**Verifies:** None (infrastructure).
<!-- END_TASK_1 -->

<!-- START_SUBCOMPONENT_A (tasks 2-4) -->

<!-- START_TASK_2 -->
### Task 2: `StabRecord` data class + `StabType` enum

**Files:**
- Create: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/container/Stabs.kt`

**Implementation:**

This file holds two small public types and the on-disk record size constant. No reader yet. Keep it pure-Kotlin (no Ghidra imports).

The enum encodes every Sun + GCC mnemonic that `parse_image/stabs_stats.py` lists (mirror that table verbatim — values 0x00..0xFE). The `code` property is the byte value as it appears in `n_type`. Provide a `byCode: Map<Int, StabType>` lookup. Records whose `n_type` does not match any known mnemonic are returned with `type = StabType.UNKNOWN` and `rawType = n_type`.

```kotlin
package ghistabs.container

/**
 * On-disk size in bytes of a single stab record (Sun a.out / PE-COFF / ELF).
 * Independent of host endianness.
 */
const val STAB_RECORD_SIZE: Int = 12

enum class StabType(val code: Int) {
    UNKNOWN(-1),
    N_UNDF(0x00),     // CU header: n_value = stabstr size for this CU
    N_GSYM(0x20),
    N_FNAME(0x22),
    N_FUN(0x24),
    N_STSYM(0x26),
    N_LCSYM(0x28),
    N_MAIN(0x2A),
    N_PC(0x30),
    N_OPT(0x3C),
    N_RSYM(0x40),
    N_M2C(0x42),
    N_SLINE(0x44),
    N_DSLINE(0x46),
    N_BSLINE(0x48),
    N_DEFD(0x4A),
    N_FLINE(0x4C),
    N_EHDECL(0x50),
    N_CATCH(0x54),
    N_SSYM(0x60),
    N_ENDM(0x62),
    N_SO(0x64),
    N_OSO(0x66),
    N_LSYM(0x80),
    N_BINCL(0x82),
    N_SOL(0x84),
    N_PARAMS(0x86),
    N_VERSION(0x88),
    N_OLEVEL(0x8A),
    N_PSYM(0xA0),
    N_EINCL(0xA2),
    N_ENTRY(0xA4),
    N_LBRAC(0xC0),
    N_EXCL(0xC2),
    N_SCOPE(0xC4),
    N_RBRAC(0xE0),
    N_BCOMM(0xE2),
    N_ECOMM(0xE4),
    N_ECOML(0xE8),
    N_LENG(0xFE);

    companion object {
        private val byCode: Map<Int, StabType> =
            entries.filter { it != UNKNOWN }.associateBy { it.code }

        fun fromCode(b: Int): StabType = byCode[b and 0xFF] ?: UNKNOWN
    }
}

/**
 * The mnemonics that may carry a `\`-continuation tail.
 * Mirrored from parse_image/stabs_stats.py:TYPES_WITH_CONTINUATION.
 */
val TYPES_WITH_CONTINUATION: Set<StabType> = setOf(
    StabType.N_GSYM, StabType.N_FUN, StabType.N_STSYM, StabType.N_LCSYM,
    StabType.N_RSYM, StabType.N_LSYM, StabType.N_PSYM,
)

/**
 * One assembled stab record. `name` has already been extracted from `.stabstr`
 * with the per-CU offset applied and any `\`-continuation chains merged.
 *
 * `recordIndex` is the 0-based index of the FIRST physical record; subsequent
 * continuation records are absorbed and not surfaced.
 */
data class StabRecord(
    val recordIndex: Int,
    val type: StabType,
    val rawType: Int,
    val other: Int,
    val desc: Int,
    val value: Long,
    val name: String,
)
```

**Testing:** none for this task — types are exercised by the reader test in Task 4.

**Step: Commit**

```bash
git add src/main/kotlin/ghistabs/container/Stabs.kt
git commit -m "feat(container): StabRecord + StabType enum"
```

**Verifies:** None directly (data types).
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: `StabReader` — pure byte walker over .stab/.stabstr

**Files:**
- Modify: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/container/Stabs.kt` (append `StabReader`)

**Implementation:**

Add a `StabReader` object/class to the same `container/Stabs.kt` file. It accepts the raw bytes of `.stab` and `.stabstr` plus a `little-endian` flag (default true), and returns `List<StabRecord>`.

Algorithm:
1. Maintain `cuOff: Int = 0` and `cuSize: Int = 0` cursors.
2. Iterate over `stab` in 12-byte slices. For each slice:
   - Decode `n_strx (u32), n_type (u8), n_other (u8), n_desc (u16), n_value (u32)`.
   - `type = StabType.fromCode(n_type)`.
   - If `type == N_UNDF`: advance `cuOff += cuSize; cuSize = n_value.toInt()`. Still emit the N_UNDF record with `name = ""` (downstream may want it). Continue.
   - Otherwise compute `nameStart = cuOff + n_strx.toInt()`. Read a NUL-terminated UTF-8 string from `stabstr[nameStart..]`.
   - If `type` is in `TYPES_WITH_CONTINUATION` and the assembled string ends in `\`, peek at the next physical record:
     - It must have `type == this.type` (same mnemonic) — if not, stop the chain (do not consume).
     - Drop the trailing `\` and concatenate the peeked record's string. Repeat until the chain doesn't end in `\` or the next record is a different type.
     - The continuation records are CONSUMED (do not yield them as separate records).
   - Yield one `StabRecord` whose `recordIndex` is the index of the first physical record of the chain.

3. Truncated final record (size not divisible by 12) is logged once and ignored — return what we have. (Real fixtures are always 12-aligned, but defensive.)

API shape:

```kotlin
package ghistabs.container

import java.nio.ByteBuffer
import java.nio.ByteOrder

class StabReader(
    private val stab: ByteArray,
    private val stabstr: ByteArray,
    private val littleEndian: Boolean = true,
) {
    data class Result(val records: List<StabRecord>, val recordCount: Int, val truncatedTail: Int)

    fun readAll(): Result { /* ... */ }

    private fun decodeAt(offset: Int, buf: ByteBuffer): Triple<...> { /* internal helper */ }

    private fun cstring(bytes: ByteArray, start: Int): String { /* read NUL-terminated UTF-8 */ }
}
```

Implementation notes:
- For `cstring`, scan for NUL or end-of-buffer; decode as UTF-8 (`String(bytes, start, len, Charsets.UTF_8)`). NUL not found ⇒ name is the rest of the buffer. Out-of-range `start` ⇒ empty string (defensive; the reader test will cover this).
- For continuation, do not call the slice itself — work on the same `ByteBuffer`, consuming additional 12-byte slices. Track `physicalIndex: Int` separately from `recordIndex`.
- `Result.recordCount` is the number of physical 12-byte slots consumed (matches `(stab.size / 12)`); `Result.records.size` is fewer due to continuation merging.

**Provide a static helper for use from Ghidra Pass A:**

```kotlin
companion object {
    /**
     * Read .stab and .stabstr from a Ghidra Program. Returns null if either block is missing.
     * Pure read — does not mutate the program.
     */
    fun fromProgram(program: ghidra.program.model.listing.Program): Result? {
        val mem = program.memory
        val stabBlock = mem.getBlock(".stab") ?: return null
        val stabstrBlock = mem.getBlock(".stabstr") ?: return null
        val stab = ByteArray(stabBlock.size.toInt())
        val stabstr = ByteArray(stabstrBlock.size.toInt())
        stabBlock.getBytes(stabBlock.start, stab)
        stabstrBlock.getBytes(stabstrBlock.start, stabstr)
        // x86 PE / x86 ELF: little-endian.
        val littleEndian = !program.memory.isBigEndian
        return StabReader(stab, stabstr, littleEndian).readAll()
    }
}
```

The Ghidra-touching helper is fine in this file because reading `program.memory` is FCIS-pure (no side effects).

**Step: Commit**

```bash
git add src/main/kotlin/ghistabs/container/Stabs.kt
git commit -m "feat(container): StabReader byte walker with per-CU offset and continuation"
```

**Verifies:** None directly — exercised by Task 4 tests.
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: `StabReader` tests (Ring-1)

**Files:**
- Create: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs/container/StabReaderTest.kt`

**Implementation:**

Pure JUnit 5 tests against synthetic byte fixtures. No Ghidra runtime needed. Use a small helper that builds a stab byte array from a list of `(strx: Int, type: Int, other: Int, desc: Int, value: Int)` tuples and concatenates a stabstr buffer from a list of strings (with explicit per-CU slicing).

The helper is a private inline object inside the test file (`Fixture`) — do not export.

Tests must verify:

- `ghidra-stabs.AC1.1`: A single-CU fixture of `(stabSize / 12)` records is fully read; record count matches; names are non-empty. **Implementation hint:** build 5 records — one N_UNDF header, then four `N_LSYM` records with various string offsets. Assert `result.records.size == 5` (no continuation present so no merging) and that each of the four `N_LSYM` records has the correct `name`.
- `ghidra-stabs.AC1.1` (continuation case): Build a chain of 3 `N_FUN` records where the first two strings end in `\`. After reassembly, expect ONE record whose `name` is `"foo\\partA" + "partB" + "tail"` minus the trailing `\` characters. (Concretely: physical strings `"foo\\"`, `"middle\\"`, `"tail"` ⇒ assembled `"foomiddletail"`.) `result.records.size` must be 2 (1 N_UNDF + 1 merged N_FUN); `result.recordCount` must be 4 (1 + 3 physical slots).
- `ghidra-stabs.AC1.2`: A two-CU fixture. CU1 has `N_UNDF.value = 10` then a stab whose `n_strx == 4` resolves into the first 10 bytes of `.stabstr`. CU2 has `N_UNDF.value = 8` then a stab whose `n_strx == 0` resolves into bytes `[10..18)`. Assert both names decode correctly.
- Reader treats unknown `n_type` byte as `StabType.UNKNOWN` with `rawType` carrying the original byte. (Synthetic record with `n_type = 0xAB`.)
- Truncated tail (stab size not multiple of 12) — append 5 bogus bytes, assert `result.truncatedTail == 5` and `result.records` is unaffected.
- Empty `.stab` (zero-length input) ⇒ `result.records.isEmpty()`, `result.recordCount == 0`.

Each test file uses standard JUnit 5 imports:

```kotlin
package ghistabs.container

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
```

**Step 1: Run the tests to confirm they fail**

```bash
cd /home/riton/git/bouse/ghidra-stabs
./gradlew test --tests 'ghistabs.container.StabReaderTest'
```

Expected: tests run after `StabReader` was implemented in Task 3 — they should pass. If they fail, fix the reader (Task 3) and rerun. Do not proceed to commit until green.

**Step 2: Verify**

```bash
./gradlew test --tests 'ghistabs.container.StabReaderTest'
```

Expected: `6 tests successful` (or however many you wrote).

**Step 3: Commit**

```bash
git add src/test/kotlin/ghistabs/container/StabReaderTest.kt
git commit -m "test(container): StabReader synthetic-byte fixtures"
```

**Verifies:** `ghidra-stabs.AC1.1`, `ghidra-stabs.AC1.2`.
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 5-6) -->

<!-- START_TASK_5 -->
### Task 5: `AddressResolver` + `BookmarkSink` facades

**Files:**
- Create: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/container/Addresses.kt`
- Create: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/importer/BookmarkSink.kt`

**Implementation:**

`Addresses.kt`:

```kotlin
package ghistabs.container

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType

/**
 * Address-resolution facade. Stab-derived addresses (recorded via
 * `recordFromStab`) win; otherwise we delegate to `program.symbolTable`.
 *
 * Creates `IMPORTED` labels at stab-derived addresses when no symbol exists.
 * Never re-parses the PE/ELF/COFF symbol table directly — Ghidra has already
 * populated `program.symbolTable`.
 */
class AddressResolver(private val program: Program) {
    private val stabMap: MutableMap<String, Address> = mutableMapOf()

    /**
     * Record an address learned from a stab record. If `name` is non-blank
     * AND no Ghidra symbol already exists at `addr` carrying that name,
     * create an `IMPORTED` label.
     *
     * Idempotent: subsequent calls with the same (name, addr) are no-ops.
     */
    fun recordFromStab(name: String, addr: Address) {
        if (name.isBlank()) {
            stabMap.putIfAbsent(name, addr)
            return
        }
        val existing = stabMap[name]
        if (existing == null) {
            stabMap[name] = addr
        } else if (existing != addr) {
            // Conflict: same name at two different addresses across CUs. Keep first; caller logs.
            return
        }
        val symtab = program.symbolTable
        val present = symtab.getSymbols(addr).any { it.name == name }
        if (!present) {
            symtab.createLabel(addr, name, SourceType.IMPORTED)
        }
    }

    /**
     * Resolve a (possibly mangled) symbol name to an address.
     * Stab-derived map first; falls back to program.symbolTable.getSymbols(name).
     * Returns null if neither source has it.
     */
    fun resolve(name: String): Address? {
        stabMap[name]?.let { return it }
        val syms = program.symbolTable.getSymbols(name)
        return syms.firstOrNull()?.address
    }
}
```

`BookmarkSink.kt`:

```kotlin
package ghistabs.importer

import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.listing.BookmarkType
import ghidra.program.model.listing.Program

/**
 * Facade over BookmarkManager + MessageLog. Diagnostics with no useful
 * address go to the log only; diagnostics at intrinsically-meaningful
 * addresses (function entry, data, vtable) get a bookmark too.
 *
 * All log/bookmark messages are prefixed `[Stabs] <category>: <message>`
 * for filtering.
 */
class BookmarkSink(
    private val program: Program,
    private val messageLog: MessageLog,
) {
    fun bookmark(category: String, addr: Address, message: String) {
        program.bookmarkManager.setBookmark(
            addr,
            BookmarkType.WARNING,
            "Stabs:$category",
            "[Stabs] $category: $message",
        )
        messageLog.appendMsg("[Stabs] $category at $addr: $message")
    }

    fun log(category: String, message: String) {
        messageLog.appendMsg("[Stabs] $category: $message")
    }
}
```

**Note:** `BookmarkSink` deliberately uses `BookmarkType.WARNING` for all stabs bookmarks — the design's per-record "skip + bookmark + log" policy treats every bookmark as a recoverable issue worth surfacing. If we want a separate ERROR severity later, that's an additive change.

**Step: Commit**

```bash
git add src/main/kotlin/ghistabs/container/Addresses.kt src/main/kotlin/ghistabs/importer/BookmarkSink.kt
git commit -m "feat(container,importer): AddressResolver + BookmarkSink facades"
```

**Verifies:** Partial `ghidra-stabs.AC6.1` (the stab-derived → IMPORTED label half).
<!-- END_TASK_5 -->

<!-- START_TASK_6 -->
### Task 6: `AddressResolver` tests (Ring-2)

**Files:**
- Create: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs/container/AddressResolverTest.kt`

**Implementation:**

Ring-2 tests: use Ghidra's `ProgramBuilder` (from `ghidra.test.util.ProgramBuilder` — part of `Generic.jar`/`Base.jar` test scope, available because `buildExtension.gradle` puts the Ghidra runtime classpath on the compile classpath). If `ProgramBuilder` is not on the test classpath at build time, the implementor surfaces this and we wire it in `build.gradle.kts`.

Tests:

- `recordFromStab` creates an `IMPORTED` label when no symbol exists at the address.
- `recordFromStab` is a no-op when a symbol already exists at the address with the same name.
- `recordFromStab` does NOT overwrite a `USER_DEFINED` or `ANALYSIS` symbol with the same name (it just records the mapping).
- `resolve` returns the stab-derived address when both the stab map and the program's symbol table are populated (stab map wins).
- `resolve` falls back to `program.symbolTable.getSymbols(name)` when the stab map is empty.
- `resolve` returns `null` when neither source has the name.
- Stripped-binary tolerance (`ghidra-stabs.AC6.1`): build a `Program` with NO COFF/ELF symbols. After calling `recordFromStab("foo", addr)`, assert `program.symbolTable.getSymbols("foo")` returns a single symbol with `SourceType.IMPORTED`.

If `ProgramBuilder` is unavailable, fall back to mocking `Program`/`SymbolTable` with a minimal hand-rolled fake (Mockito-Kotlin or a manual `object : SymbolTable { ... }` — the implementor decides).

**Step: Run tests, then commit**

```bash
./gradlew test --tests 'ghistabs.container.AddressResolverTest'
git add src/test/kotlin/ghistabs/container/AddressResolverTest.kt
git commit -m "test(container): AddressResolver stripped-binary fallback + label creation"
```

**Verifies:** `ghidra-stabs.AC6.1` (stab-derived `IMPORTED` label half).
<!-- END_TASK_6 -->

<!-- END_SUBCOMPONENT_B -->

<!-- START_TASK_7 -->
### Task 7: Real-binary smoke test (Ring-3, optional but freezes the count)

**Files:**
- Create: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs/container/StabReaderRealBinaryTest.kt`
- Create: `/home/riton/git/bouse/ghidra-stabs/src/test/resources/binaries/.gitkeep`

**Implementation:**

This test loads `xapasmcsr.exe` (or a copy thereof) and asserts the reader-level invariants from the design:

- `result.recordCount == 48_341` (per design's "Done when").
- `result.records.size <= result.recordCount` (continuation merging shrinks the count, never grows it).
- All records have `type != StabType.UNKNOWN` OR are flagged as such (we do not assert zero unknowns since real binaries occasionally have them).
- `result.truncatedTail == 0`.

**Fixture provenance:**
- Reference path: `~/.wine/drive_c/ADK2.5.1/tools/lib/gcc-lib/xap-local-xap/3.3.3/xapasmcsr.exe`.
- For test repeatability the binary must be copied into the repo at `src/test/resources/binaries/xapasmcsr.exe`. **Do this manually before running tests:**
  ```bash
  cp ~/.wine/drive_c/ADK2.5.1/tools/lib/gcc-lib/xap-local-xap/3.3.3/xapasmcsr.exe \
     /home/riton/git/bouse/ghidra-stabs/src/test/resources/binaries/xapasmcsr.exe
  ```
- The test must `assumeTrue(file.exists())` so CI without the fixture skips rather than fails.
- Add `src/test/resources/binaries/xapasmcsr.exe` to `.gitignore` if licensing prohibits committing it (CSR ADK redistribution status is unclear). The implementor must ASK before committing the binary.

**Loading approach:**
The test parses the PE container directly enough to find the `.stab` and `.stabstr` sections — but rather than re-parsing PE headers, use Ghidra's `ProgramBuilder` to load the file via Ghidra's PE loader. Then call `StabReader.fromProgram(program)`.

**If running this test from Gradle is too slow / fragile:** mark the class with `@Tag("integration")` and configure a separate Gradle task `integrationTest` that's run nightly only. The implementor decides based on observed runtime (target: < 30 s).

**Step: Run, then commit**

```bash
./gradlew test --tests 'ghistabs.container.StabReaderRealBinaryTest'
# (skips if fixture absent)
git add src/test/kotlin/ghistabs/container/StabReaderRealBinaryTest.kt \
        src/test/resources/binaries/.gitkeep
git commit -m "test(container): real-binary smoke (xapasmcsr.exe, 48k records)"
```

**Verifies:** `ghidra-stabs.AC1.1` (real-fixture count assertion).
<!-- END_TASK_7 -->

---

## Phase Done When

- [ ] Stub `StabsLoader.kt` and `StabsExporter.java` deleted.
- [ ] `.gitignore` covers build/, .gradle/, .idea/, .vscode/, dist/, lib/*.jar, .kotlin/.
- [ ] `build.gradle.kts` includes JUnit 5 deps and `useJUnitPlatform()`.
- [ ] `container/Stabs.kt` exports `StabRecord`, `StabType`, `StabReader`.
- [ ] `container/Addresses.kt` exports `AddressResolver`.
- [ ] `importer/BookmarkSink.kt` exports `BookmarkSink`.
- [ ] `./gradlew build` succeeds.
- [ ] `./gradlew test` runs `StabReaderTest` + `AddressResolverTest` (both green).
- [ ] If fixture present: `StabReaderRealBinaryTest` reports `recordCount == 48_341` against `xapasmcsr.exe`.
