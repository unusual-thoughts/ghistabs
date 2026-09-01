@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.diagnose

import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghistabs.importer.ImportArtifacts
import ghistabs.index.TypeLocation
import ghistabs.materialize.compromisedTypes
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.IdInterface
import ghistabs.parse.ToStringSerializer
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToStream
import kotlinx.serialization.modules.SerializersModule
import java.io.File

/*
 * JSON snapshot dumps of importer state (records / harvest / registry). Shared by the headless CLI
 * ([ghistabs.cli]) and the test suite — both want the same `build/test-output/`-style artifacts.
 */

/** Shared JSON config for the snapshot dumps (ids/paths → their `toString`). */
val dumpJson by lazy {
    Json {
        serializersModule = SerializersModule {
            contextual(IdInterface::class, ToStringSerializer())
            contextual(CategoryPath::class, ToStringSerializer())
        }
        prettyPrint = true
    }
}

/**
 * Snapshot what the importer actually produced — compromised DataTypes (anonymous / empty-placeholder
 * / all-Undefined / xref-stub), canonical groups, divergent collisions — to [outFile] as JSON. Lets us
 * spot misattributions visually without relying on individual degradation events.
 */
@OptIn(ExperimentalSerializationApi::class)
fun ImportArtifacts.writeRegistryDump(outFile: File) {
    outFile.parentFile.mkdirs()
    outFile.outputStream().use { dumpJson.encodeToStream(registryDump(), it) }
}

@Serializable
private data class RegistryDump(
    val summary: Summary,
    val compromised: Map<String, List<Type>>,
    val canonicalGroups: List<Group>,
    val divergentCollisions: List<IdCollision>,
    // §20/§21 grouping diagnosis. `sourceFolds`: §15 basename canonicalisation (raw → canonical).
    // `contentHashCollisions`: content-equivalent groups that did NOT merge into one — each is a §20
    // merge that either fired (one group left) or a candidate that didn't (why?). `duplicateNamedTypes`:
    // materialized DataTypes sharing a simple name (the source of `.conflict` suffixes in the decomp).
    val sourceFolds: Map<String, String> = emptyMap(),
    val contentHashCollisions: List<HashCollision> = emptyList(),
    val allTypes: Map<TypeLocation, Type> = emptyMap(),
    val duplicateNamedTypes: Map<String, List<String>> = emptyMap(),
) {
    constructor(
        compromised: Map<String, List<Type>>,
        canonicalGroups: List<Group>,
        divergentCollisions: List<IdCollision>,
        sourceFolds: Map<String, String>,
        contentHashCollisions: List<HashCollision>,
        allTypes: Map<TypeLocation, Type>,
        duplicateNamedTypes: Map<String, List<String>>,
    ) : this(
        summary = Summary(
            registeredDataTypes = allTypes.size,
            compromisedCounts = compromised.mapValues { it.value.size },
            canonicalGroups = canonicalGroups.size,
            divergentCollisions = divergentCollisions.size,
        ),
        compromised,
        canonicalGroups,
        divergentCollisions,
        sourceFolds,
        contentHashCollisions,
        allTypes,
        duplicateNamedTypes,
    )

    @Serializable
    data class IdCollision(val id: String, val byName: Map<String, Int>)

    @Serializable
    data class HashCollision(val groups: List<String>, val distinctNames: List<String>)

    @Serializable
    data class Summary(
        val registeredDataTypes: Int,
        val compromisedCounts: Map<String, Int>,
        val canonicalGroups: Int,
        val divergentCollisions: Int,
    )

    @Serializable
    data class Type(val path: String, val name: String, val kind: String, val length: Int) {
        constructor(dt: DataType) : this(dt.categoryPath.path, dt.name, dt::class.simpleName ?: "?", dt.length)
    }

    @Serializable
    data class Group(
        val key: TypeLocation,
        val id: GlobalTypeId,
        val name: String,
        val members: Int,
        val anon: Int,
        val distinct: Int,
    )
}

private fun ImportArtifacts.registryDump(): RegistryDump {
    val compromised = registry.compromisedTypes().mapValues { (_, dts) ->
        dts.sortedBy { it.pathName }
            .map { RegistryDump.Type(it) }
    }
    val canonicalGroups = registry.byLocation.entries
        .sortedBy { it.key.toString() }
        .map { (key, g) ->
            RegistryDump.Group(
                key,
                g.type.id,
                g.type.ghidraName,
                g.members.size,
                g.members.count { index.types.byId(it)?.name.isNullOrEmpty() },
                g.distinct,
            )
        }
    // §20 diagnosis: content-equivalent classes still spanning >1 group (a merge that didn't fire),
    // and DataTypes sharing a simple name (the `.conflict` source in the decomp).
    // Group by content hash (equality only — the raw value is a JVM-run-nondeterministic
    // `Objects.hash` of enum members, so it's used to bucket but never stored/sorted on).
    val hashCollisions = registry.byLocation.values
        .groupBy { index.types.content(it.type.body) }
        .filterValues { it.size > 1 }
        .map { (_, gs) ->
            RegistryDump.HashCollision(
                gs.map { it.type.ghidraName }.sorted(),
                gs.map { it.type.ghidraName }.toSortedSet().toList(),
            )
        }
        .sortedBy { it.distinctNames.joinToString() }
    val duplicateNamed = registry.allCreatedDataTypes
        .groupBy { it.name.substringBefore(".conflict") }
        .filterValues { it.size > 1 }
        .mapValues { (_, dts) -> dts.map { it.pathName }.sorted() }
        .toSortedMap()
    // One entry per (category, name). `allCreatedDataTypes` can hold >1 DataType for a key (a stale
    // pre-conflict object plus its DTM-live replacement); the duplicates are surfaced in
    // `duplicateNamed` above, so keep the first deterministically here rather than `single()` (which
    // threw on duplicate-heavy fixtures and aborted the whole AFTER-mode dump).
    val allTypes = registry.allCreatedDataTypes.groupBy { TypeLocation(it.categoryPath, it.name) }
        .mapValues { RegistryDump.Type(it.value.first()) }
    val divergent = index.types.divergentCollisions.entries
        .sortedBy { it.key.toString() }
        .map { (id, byName) ->
            RegistryDump.IdCollision(
                id.toString(),
                byName.mapValues { (_, bodies) -> bodies.size },
            )
        }
    val sourceFolds = index.sources.sourceFolds.toSortedMap().map { (k, v) -> k.path to v.path }.toMap()
    return RegistryDump(compromised, canonicalGroups, divergent, sourceFolds, hashCollisions, allTypes, duplicateNamed)
}
