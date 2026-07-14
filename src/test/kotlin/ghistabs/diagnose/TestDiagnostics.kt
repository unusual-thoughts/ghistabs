package ghistabs.diagnose

import ghidra.program.model.address.Address
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.StabsOptions
import ghistabs.harvest.Harvest
import ghistabs.harvest.TypeResolver
import ghistabs.harvest.foldSourcePaths
import ghistabs.importer.ImportContext
import ghistabs.materialize.TypeRegistry
import ghistabs.parse.IdInterface
import ghistabs.parse.ToStringSerializer
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToStream
import kotlinx.serialization.modules.SerializersModule
import java.io.File

/**
 * Shared test diagnostics / dump infrastructure — the non-test scaffolding that captures import
 * output and serialises snapshots for inspection under `build/test-output/`. Kept out of the test
 * classes so they hold assertions only.
 */

/** Pure Kotlin test double that captures `log()` calls into a list. */
class CapturingSink : DiagnosticSink {
    data class LogLine(val tag: String, val address: Address?, val msg: String?, val level: Level = Level.INFO) {
        override fun toString(): String = if (address != null) {
            "[${level.name}][$tag] at @$address $msg"
        } else {
            "[${level.name}][$tag] $msg"
        }
    }

    internal val lines = mutableListOf<LogLine>()

    override fun log(category: String, message: String?, level: Level, address: Address?, count: Long) {
        lines.add(LogLine(tag = category, msg = message, address = address, level = level))
    }

    fun capturedOutput(): String = lines.filter { it.msg != null }.joinToString("\n")

    /**
     * [capturedOutput] with repeated `(tag, msg)` pairs suppressed beyond [maxPerKey] occurrences.
     * Address-bearing lines are never dropped — each address is a unique location. tagFrequencies
     * stays raw so counter-baseline assertions remain stable.
     */
    fun dedupedOutput(maxPerKey: Int = 3): String {
        val seen = mutableMapOf<Pair<String, String?>, Int>()
        return buildString {
            for (line in lines) {
                if (line.msg == null) continue
                if (line.address != null) {
                    if (isNotEmpty()) append('\n')
                    append(line.toString())
                    continue
                }
                val key = line.tag to line.msg
                val count = (seen[key] ?: 0) + 1
                seen[key] = count
                when {
                    count <= maxPerKey -> {
                        if (isNotEmpty()) append('\n')
                        append(line.toString())
                    }

                    count == maxPerKey + 1 -> {
                        if (isNotEmpty()) append('\n')
                        append("[${line.tag}] ...suppressing further duplicates of: ${line.msg}")
                    }
                    // else silently drop
                }
            }
        }
    }
}

// Tests capture at max verbosity — DEBUG and up — so log assertions see every message.
fun Program.defaultContext() = ImportContext(
    this,
    TaskMonitor.DUMMY,
    StabsOptions(minLogLevel = Level.DEBUG),
    CapturingSink(),
    StabsDiagnostics(),
)

fun ImportContext<*>.defaultTypeRegistry(): TypeRegistry {
    val harvest = Harvest(mapOf())
    return TypeRegistry(dtm, this, diagnostics, harvest, TypeResolver.Empty)
}

/** Shared Json config for the `build/test-output/` snapshot dumps (ids/paths → their `toString`). */
@OptIn(ExperimentalSerializationApi::class)
val dumpJson = Json {
    serializersModule = SerializersModule {
        contextual(IdInterface::class, ToStringSerializer())
        contextual(CategoryPath::class, ToStringSerializer())
    }
    prettyPrint = true
}

/**
 * Snapshot what the importer actually produced — compromised DataTypes (anonymous / empty-placeholder
 * / all-Undefined / xref-stub), canonical groups, divergent collisions — to [outFile] as JSON. Lets us
 * spot misattributions visually without relying on individual degradation events.
 */
@OptIn(ExperimentalSerializationApi::class)
fun writeRegistryDump(registry: TypeRegistry, resolver: TypeResolver, outFile: File) {
    outFile.parentFile.mkdirs()
    val compromised = registry.compromisedTypes().mapValues { (_, dts) ->
        dts.sortedBy { it.pathName }.map { CompromisedEntry(it.pathName, it::class.simpleName ?: "?", it.length) }
    }
    val harvest = resolver.harvest
    val canonicalGroups = resolver.byCanonicalKey.entries
        .sortedBy { it.key.toString() }
        .map { (key, g) ->
            CanonicalGroupEntry(
                key.toString(),
                g.ast.id.toString(),
                g.ast.ghidraName,
                g.members.size,
                g.members.count { harvest.typeAsts[it]?.name.isNullOrEmpty() },
                g.distinct,
            )
        }
    // §20 diagnosis: content-equivalent classes still spanning >1 group (a merge that didn't fire),
    // and DataTypes sharing a simple name (the `.conflict` source in the decomp).
    // Group by content hash (equality only — the raw value is a JVM-run-nondeterministic
    // `Objects.hash` of enum members, so it's used to bucket but never stored/sorted on).
    val hashCollisions = resolver.byCanonicalKey.values
        .groupBy { resolver.contentHash(it.ast.body) }
        .filterValues { it.size > 1 }
        .map { (_, gs) ->
            HashClassEntry(
                gs.map { it.ast.ghidraName }.sorted(),
                gs.map { it.ast.ghidraName }.toSortedSet().toList(),
            )
        }
        .sortedBy { it.distinctNames.joinToString() }
    val duplicateNamed = registry.allCreatedDataTypes
        .groupBy { it.name.substringBefore(".conflict") }
        .filterValues { it.size > 1 }
        .mapValues { (_, dts) -> dts.map { it.pathName }.sorted() }
        .toSortedMap()
    val divergent = resolver.divergentCollisions.entries
        .sortedBy { it.key.toString() }
        .map { (id, byName) -> DivergentEntry(id.toString(), byName.mapValues { (_, bodies) -> bodies.size }) }
    val dump = RegistryDump(
        summary = DumpSummary(
            registeredDataTypes = registry.allCreatedDataTypes.size,
            compromisedCounts = compromised.mapValues { it.value.size },
            canonicalGroups = canonicalGroups.size,
            divergentCollisions = divergent.size,
        ),
        compromised = compromised,
        canonicalGroups = canonicalGroups,
        divergentCollisions = divergent,
        sourceFolds = foldSourcePaths(
            harvest.lineEntries.keys + harvest.symbolsByCu.keys +
                harvest.typeAsts.values.flatMap { listOfNotNull(it.id.source.filename, it.declSourceFile) },
        ).filter { it.key != it.value }.toSortedMap(),
        contentHashCollisions = hashCollisions,
        duplicateNamedTypes = duplicateNamed,
    )
    outFile.outputStream().use { dumpJson.encodeToStream(dump, it) }
}

@Serializable
private data class RegistryDump(
    val summary: DumpSummary,
    val compromised: Map<String, List<CompromisedEntry>>,
    val canonicalGroups: List<CanonicalGroupEntry>,
    val divergentCollisions: List<DivergentEntry>,
    // §20/§21 grouping diagnosis. `sourceFolds`: §15 basename canonicalisation (raw → canonical).
    // `contentHashCollisions`: content-equivalent groups that did NOT merge into one — each is a §20
    // merge that either fired (one group left) or a candidate that didn't (why?). `duplicateNamedTypes`:
    // materialised DataTypes sharing a simple name (the source of `.conflict` suffixes in the decomp).
    val sourceFolds: Map<String, String> = emptyMap(),
    val contentHashCollisions: List<HashClassEntry> = emptyList(),
    val duplicateNamedTypes: Map<String, List<String>> = emptyMap(),
)

@Serializable
private data class HashClassEntry(val groups: List<String>, val distinctNames: List<String>)

@Serializable
private data class DumpSummary(
    val registeredDataTypes: Int,
    val compromisedCounts: Map<String, Int>,
    val canonicalGroups: Int,
    val divergentCollisions: Int,
)

@Serializable
private data class CompromisedEntry(val pathName: String, val kind: String, val length: Int)

@Serializable
private data class CanonicalGroupEntry(
    val key: String,
    val winnerId: String,
    val winner: String,
    val members: Int,
    val anon: Int,
    val distinct: Int,
)

@Serializable
private data class DivergentEntry(val id: String, val byName: Map<String, Int>)
