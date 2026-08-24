package ghistabs.audit

import ghistabs.integration.Fixtures
import ghistabs.test.mustBeEmpty
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.File

/**
 * The demangler-stub whitelist, and the audit that keeps it honest. Lives in its own class because
 * it is a CORPUS-level invariant, not a per-fixture one: it reads the per-fixture dumps that
 * [ghistabs.integration.StabsImportRegressionBase.demanglerHasNoEmptyStubs] writes. Tagged `audit` and run by the
 * :auditWhitelist task, which `integrationTest` is finalizedBy — as a plain `integration` class it
 * raced the fixtures that produce its input and silently skipped.
 */
object DemanglerWhitelist {
    // Demangler stubs with no concrete type to bind to across the corpus: types the demangler
    // names from mangled symbols that this binary only forward-declares (RTTI / EH surface) or
    // references unparameterised — no full class stab to resolve to, so they stay empty. A stub
    // outside this set is a real materialization gap. Global for now; add consciously when
    // reviewed. Known real gaps deliberately excluded: `_Rb_tree_node`, `__normal_iterator.conflict`.
    val ALLOWED = setOf(
        // bare (unparameterised) template names + builtin-spelling artifacts
        "allocator", "new_allocator", "codecvt", "collate", "ctype", "messages",
        "moneypunct", "money_get", "money_put", "num_get", "num_put", "numpunct",
        "time_get", "time_put", "istreambuf_iterator", "__normal_iterator",
        "__moneypunct_cache", "__numpunct_cache", "__timepunct", "__timepunct_cache",
        "_Rope_RopeRep", "signed", "__gthread_mutex_t",
        // std exception / EH hierarchy (forward-declared for RTTI, never fully defined)
        "logic_error", "runtime_error", "domain_error", "invalid_argument", "length_error",
        "out_of_range", "overflow_error", "range_error", "underflow_error",
        // libsupc++ / libgcc unwinder + RTTI internals
        "_Unwind_Context", "_Unwind_Exception", "lsda_header_info", "__dyncast_result",
        "__upcast_result",
        // libsupc++ EH + RTTI classes the demangler names from a mangled symbol but which have NO
        // stab body anywhere in the corpus (verified against all 21 harvests: never emitted with
        // fields). Deliberately NOT whitelisted — __basic_file, __moneypunct_cache, __numpunct_cache,
        // __mt_alloc, __pool_alloc, _Deque_base/_Deque_iterator, _Vector_base, __normal_iterator,
        // __pbase_type_info — because those DO carry real stab bodies in some fixtures, so an empty
        // stub for them is a genuine materialization gap (see triage §B/§E), not a compiler internal.
        "__concurrence_lock_error", "__concurrence_unlock_error", "recursive_init_error",
        "__array_type_info", "__enum_type_info", "__function_type_info", "__fundamental_type_info",
        // locale facets forward-declared in non-libstdc++ fixtures (full instantiations elsewhere)
        "__ctype_abstract_base<char>",
        "stdio_filebuf<char,std::char_traits<char>>",
    )
}

@Tag("audit")
class DemanglerWhitelistAuditTest {
    /**
     * Whitelist hygiene: every [DemanglerWhitelist.ALLOWED] entry must correspond to a real empty
     * stub in at least one fixture — else it's dead cruft (e.g. now filled by the demangler
     * reverse-index bridge). Reads the per-fixture dumps
     * [ghistabs.integration.StabsImportRegressionBase.demanglerHasNoEmptyStubs] writes — once, not once per fixture.
     */
    @Test
    fun whitelistEntriesAreLive() {
        val dumps = File("build/test-output/demangler-empty-stubs").listFiles { f -> f.extension == "txt" }.orEmpty()
        // Corpus-wide audit: only meaningful once EVERY fixture has dumped. A count threshold isn't
        // enough — stale dumps from an earlier partial run satisfy it while misrepresenting the
        // corpus (seen calling `less`/`exception` dead), so a partial set skips instead.
        val expected = Fixtures.ALL.map { it.substringBeforeLast('.') }.toSet()
        val have = dumps.map { it.nameWithoutExtension }.toSet()
        assumeTrue(have.containsAll(expected), "need a full-corpus dump (missing ${expected - have})")
        val live = dumps.flatMap { f -> f.readLines().filter { it.isNotBlank() }.map { it to f.name } }
            .groupBy { it.first }.mapValues { (_, l) -> l.map { it.second }.toSortedSet().joinToString(" ") }
        val dead = DemanglerWhitelist.ALLOWED - live.keys
        dead.mustBeEmpty("Dead DemanglerWhitelist.ALLOWED entries (prune): $dead")

        for ((files, types) in (live - DemanglerWhitelist.ALLOWED).entries.sortedBy { it.value }.groupBy { it.value }) {
            println("# Remaining stubs in $files :")
            for ((type, _) in types) {
                println("  - $type")
            }
            println()
        }
    }
}
