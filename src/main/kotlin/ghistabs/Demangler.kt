package ghistabs

import ghidra.app.cmd.label.DemanglerCmd
import ghidra.app.util.demangler.DemangledObject
import ghidra.app.util.demangler.MangledContext
import ghidra.app.util.demangler.gnu.GnuDemangler
import ghidra.app.util.demangler.gnu.GnuDemanglerOptions
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import java.util.concurrent.ConcurrentHashMap

/**
 * Ghidra's C++ demangler — the only module that touches [GnuDemangler] / [DemanglerCmd] /
 * `DemanglerOptions`. Pure name-string parsing (namespace/template splitting, mangled-name
 * classification) lives Ghidra-free in [ghistabs.parse] (Names.kt).
 *
 * Memoized: the passes walk overlapping name sets — `SymbolApplier`, `DataTypeRegistry.byDemangledClass`,
 * `DemanglerReplacer.dropDisplacedMangledLabels` and its instantiation census each meet names the others
 * have already seen, and [name] / [namespaces] re-enter [of] on a name their caller
 * just demangled. 65% hit rate on crypto_mi_test_gcc421 (23023 of 35322 calls), turning ~6.5s of
 * demangling into ~2.3s.
 *
 * **Results are shared — treat a [DemangledObject] as immutable.** `setName`/`setNamespace` exist, and
 * Ghidra itself sets the mangled context on the instance; mutating one corrupts it for every later caller,
 * with no symptom at the mutation site.
 */
object Demangler {
    private val demangler by lazy { GnuDemangler() }

    /**
     * What `GnuDemanglerAnalyzer` uses, which is *not* the class default. `DemanglerOptions` defaults
     * `demangleOnlyKnownPatterns` to true, and that gates `GnuDemangler.isKnownMangledString`, whose
     * `isInvalidDoubleUnderscoreString` check is wrong for a name that *starts* with `__`: the leading text
     * is `substring(0, 0)`, and `demangled.contains("")` is always true, so a correct result is discarded.
     * The Cygwin PE loader prefixes every symbol with `_`, making that every `__Z…` name — 12208 of 27355
     * on crypto_mi_test_gcc421. Ghidra's own analyzer never trips it because it sets the flag false; we
     * take the same setting rather than work around a check we shouldn't be running.
     */
    val options get() = GnuDemanglerOptions().apply { setDemangleOnlyKnownPatterns(false) }

    /**
     * Capped rather than tied to an import: memoizing a pure function has no correctness lifetime, so the
     * only thing to bound is memory in a long-lived Ghidra session. Dropping the lot costs a re-demangle.
     */
    private const val MAX_ENTRIES = 1 shl 16
    private val cache = ConcurrentHashMap<String, Result<DemangledObject>>()

    /** Demangle [mangled] to a [DemangledObject], or null if it isn't a mangled name / demangling fails.
     * [ghidra.app.util.demangler.gnu.GnuDemanglerNativeProcess.demangle] is itself synchronized,
     * so only the map needs guarding.
     */
    fun of(mangled: String): DemangledObject? {
        if (cache.size > MAX_ENTRIES) cache.clear()
        return cache.computeIfAbsent(mangled) { name ->
            runCatching { demangler.demangle(MangledContext(null, options, name, null)) }
        }.getOrNull()
    }

    /** Human-readable name for [mangled], falling back to [mangled] */
    fun name(mangled: String): String = of(mangled)?.demangledName ?: mangled

    /** Parent-namespace chain, root-first, for [mangled] — or null if it has no enclosing namespace. */
    fun namespaces(mangled: String): List<String>? = of(mangled)?.namespace?.let { parent ->
        generateSequence(parent) { it.namespace }.map { it.name }.toList().asReversed()
    }
}

/**
 * Apply Ghidra's demangler to the symbol at [addr] (rename + namespace).
 * Signature / calling-convention / disassembly application are off by default -
 * the stab carries richer types than the mangled name. Returns whether the command applied.
 */
fun Program.applyDemangling(
    addr: Address,
    mangled: String,
    applySignature: Boolean = false,
    applyCallingConvention: Boolean = false,
    doDisassembly: Boolean = false,
    monitor: TaskMonitor = TaskMonitor.DUMMY,
) = DemanglerCmd(
    addr,
    mangled,
    Demangler.options.apply {
        setApplySignature(applySignature)
        setApplyCallingConvention(applyCallingConvention)
        setDoDisassembly(doDisassembly)
    },
).run { applyTo(this@applyDemangling, monitor) && result != null }
