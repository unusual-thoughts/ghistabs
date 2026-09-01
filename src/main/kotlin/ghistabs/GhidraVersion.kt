package ghistabs

/**
 * Capabilities that need no *compile-time* variance, probed from the jars actually on the classpath.
 *
 * A feature we can ask about at runtime costs nothing at build time, so it is one file here rather
 * than a matched pair of source directories. Class presence rather than
 * `Application.getApplicationVersion()`, which throws unless Ghidra's Application has been
 * initialised — it has not in a plain unit test.
 *
 * Compile-time variance remains unavoidable where a *type or signature* is absent; see the
 * `src/main/kotlin-pre*` directories for those. A probe must never name a class those directories
 * shim, or it finds our own declaration and answers true on every release.
 */
private fun hasClass(name: String) =
    runCatching { Class.forName(name, false, Demangler::class.java.classLoader) }.isSuccess

/**
 * Whether Ghidra's `PreProcessor` echoes the lines a conditional dropped — the `///-` marker its CPP
 * grammar gained in 11.3. Probed via a class from the same release, there being none of its own:
 * the echo is a grammar change, not an API one.
 */
internal val ECHOES_DROPPED_LINES by lazy { hasClass("ghidra.program.database.sourcemap.SourceFileIdType") }

/** Whether a.out binaries can be loaded at all; Ghidra gained `UnixAoutLoader` in 11.4. */
val LOADS_AOUT by lazy { hasClass("ghidra.app.util.opinion.UnixAoutLoader") }
