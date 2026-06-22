package ghistabs.integration

import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.StabsOptions
import ghistabs.diagnose.CapturingSink
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.harvest.Harvester
import ghistabs.harvest.TypeAst
import ghistabs.harvest.TypeResolver
import ghistabs.importer.ImportContext
import ghistabs.parse.StabReader
import ghistabs.parse.TypeDecl
import ghistabs.runTransaction
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.File

/**
 * One-shot: for every XRef in the harvest, dump the requested tagName against
 * the harvest's candidate names — exact, whitespace-stripped, and base-tag.
 *
 * Goal: pin down whether the 14 xref-ambiguous on bouniafbouniaf.exe are
 * whitespace/qualification mismatches (fixable by normalised lookup) or
 * genuinely different specializations (no candidate exists).
 */
@Tag("integration")
class XRefDiagnosisIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun diagnosebouniafbouniaf() {
        val fixture = File("src/test/resources/binaries/bouniafbouniaf.exe")
        assumeTrue(fixture.exists(), "fixture absent")

        val log = MessageLog()
        val monitor = TaskMonitor.DUMMY
        val loadResults = ProgramLoader.builder()
            .source(fixture)
            .compiler("mingw")
            .log(log)
            .monitor(monitor)
            .load()
        try {
            val program = loadResults.getPrimaryDomainObject(this)
            val reader = StabReader.fromProgram(program)!!
            val ctx = ImportContext(
                program,
                monitor,
                StabsOptions(),
                CapturingSink(),
                StabsDiagnostics(),
            )
            val harvester = Harvester(monitor, ctx.sink, ctx.resolver)
            val harvest = program.runTransaction("xref-diag-harvest") {
                harvester.passA(reader.records)
            }
            val resolver = TypeResolver(harvest.typeAsts, harvest.rawCollisions, ctx.sink, ctx.diagnostics)

            // Collect every distinct XRef appearing anywhere in the harvest.
            val xrefs = mutableSetOf<TypeDecl.XRef<*>>()
            for (ast in harvest.typeAsts.values) collectXRefs(ast.body, xrefs)

            val nameSet = harvest.typeAsts.values.mapNotNull { it.name }.toSet()
            val normalizedIndex = harvest.typeAsts.values
                .filter { !it.name.isNullOrEmpty() }
                .groupBy { normalize(it.name!!) }

            val out = File("build/degradations/bouniafbouniaf.xref-diagnosis.txt")
            out.parentFile.mkdirs()
            out.bufferedWriter().use { w ->
                w.write("Total distinct XRefs in harvest: ${xrefs.size}\n\n")
                for (xref in xrefs.sortedBy { it.tagName }) {
                    @Suppress("UNCHECKED_CAST")
                    val typed = xref as TypeDecl.XRef<ghistabs.parse.GlobalTypeId>
                    if (resolver.lookupByXRef(typed, silent = true) != null) continue
                    val norm = normalize(xref.tagName)
                    val normMatches = normalizedIndex[norm].orEmpty()
                    val exactMatch = nameSet.contains(xref.tagName)
                    w.write("XRef [${xref.kind}] '${xref.tagName}'\n")
                    w.write("  exact match: $exactMatch\n")
                    w.write("  normalized:  '$norm'\n")
                    w.write("  normalized matches in harvest: ${normMatches.size}\n")
                    for (m in normMatches.take(5)) {
                        val sz = (m.body as? TypeDecl.Struct)?.sizeBytes
                        w.write("    - kind=${m.body::class.simpleName} size=$sz name='${m.name}' id=${m.id}\n")
                    }
                    w.write("\n")
                }
            }
            println("XRef diagnosis written to ${out.absolutePath}")

            program.release(this)
        } finally {
            loadResults.close()
        }
    }

    private fun normalize(tag: String): String = tag.replace(Regex("\\s+"), "")
        .replace(">>", "> >") // legacy template-close style
        .replace("> >", ">>") // collapse uniformly

    private fun collectXRefs(decl: TypeDecl<*>, out: MutableSet<TypeDecl.XRef<*>>) {
        when (decl) {
            is TypeDecl.XRef -> out.add(decl)
            is TypeDecl.Pointer -> collectXRefs(decl.pointee, out)
            is TypeDecl.Reference -> collectXRefs(decl.referent, out)
            is TypeDecl.Array -> {
                collectXRefs(decl.element, out)
                decl.indexType?.let { collectXRefs(it, out) }
            }
            is TypeDecl.Const -> collectXRefs(decl.inner, out)
            is TypeDecl.Volatile -> collectXRefs(decl.inner, out)
            is TypeDecl.InlineDef -> collectXRefs(decl.body, out)
            is TypeDecl.WithSizeAttr -> collectXRefs(decl.inner, out)
            is TypeDecl.Struct -> {
                for (f in decl.fields) collectXRefs(f.type, out)
                for (b in decl.bases) collectXRefs(b.type, out)
                for (m in decl.methods) collectXRefs(m.signature, out)
            }
            is TypeDecl.FunctionT -> {
                collectXRefs(decl.ret, out)
                for (p in decl.params) collectXRefs(p, out)
            }
            is TypeDecl.Method -> {
                collectXRefs(decl.cls, out)
                collectXRefs(decl.ret, out)
                for (p in decl.params) collectXRefs(p, out)
            }
            else -> {}
        }
    }

    @Suppress("UNUSED_PARAMETER") // satisfy ktlint when ast is unused
    private fun ignore(ast: TypeAst) = Unit
}
