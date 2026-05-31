# Ghidra Test Dependencies

## Overview

Integration tests in `src/test/kotlin/ghistabs/integration/` require Ghidra Test JARs to bootstrap the `AbstractGhidraHeadlessIntegrationTest` harness. These JARs provide:

- `AbstractGhidraHeadlessIntegrationTest` base class
- `TestEnv` for headless Program creation and analysis
- `AutoAnalysisManager` integration for running full analysis passes

## Configuration

Build file: `build.gradle.kts`

Added via direct JAR reference to:

```kotlin
testImplementation(fileTree(mapOf("dir" to "$ghidraInstallDirForTests/Ghidra/Features/Base/lib", "include" to "Base.jar")))
```

This includes `AbstractGhidraHeadlessIntegrationTest` and `TestEnv` from Base.jar.

Additional test JARs from `Ghidra/Test` directory:

```kotlin
testImplementation(
    fileTree(
        mapOf(
            "dir" to "$ghidraInstallDirForTests/Ghidra/Test",
            "include" to listOf("**/lib/*.jar"),
        ),
    ),
)
```

This ensures integration test fixtures from IntegrationTest and DebuggerIntegrationTest modules are available if needed.

## How to Update for New Ghidra Versions

1. **Inspect installed JARs:**
   ```bash
   find $GHIDRA_INSTALL_DIR/Ghidra/Test -name "*.jar" -type f
   find $GHIDRA_INSTALL_DIR/Ghidra/Framework/Test -name "*.jar" -type f
   ```

2. **Check for renamed or moved directories:**
   - New Ghidra versions may reorganize Test artifact locations.
   - Verify both `Test` and `Framework/Test` subtrees exist.

3. **If no matches found:**
   - Inspect `$GHIDRA_INSTALL_DIR/Ghidra/` for alternative test artifact locations.
   - Consider consulting Ghidra release notes for any restructuring.

4. **Update `fileTree` paths** in `build.gradle.kts` if locations change.

## Integration Test Skip Behavior

- If `GHIDRA_INSTALL_DIR` is not set, build will attempt to use `/opt/ghidra`.
- If the set directory does not exist or contains no matching JARs, gradle dependency resolution will warn but may not fail (depending on gradle strictness mode).
- Individual integration tests guard with `assumeTrue(fixture.exists())`, so tests skip gracefully if `bouniafbouniaf.exe` fixture is absent.

## Known Issues

### Java 21 × Ghidra 11.x: ObjectInputFilter conflict (#40)

Workaround attempt in `build.gradle.kts`:
```kotlin
forkEvery = 1
jvmArgs("-Djdk.serialFilter=*")
```

If integration tests still fail with `ObjectInputFilter factory error` at JVM init:
- The harness code and test structure remain valid.
- Tests will skip via `assumeTrue(fixture.exists())` regardless, since `bouniafbouniaf.exe` is bouniaf and not committed to the repo.
- See task #40 for full context.
