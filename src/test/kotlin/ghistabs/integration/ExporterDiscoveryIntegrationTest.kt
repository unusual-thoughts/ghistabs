package ghistabs.integration

import ghidra.app.util.exporter.Exporter
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.classfinder.ClassSearcher
import ghistabs.entrypoints.StabsRenderExporter
import ghistabs.test.mustBe
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * The exporters are declared nowhere — Ghidra finds them by the `…Exporter` class-name suffix
 * ([ClassSearcher]). Rename one out of that suffix and it silently disappears from
 * `File > Export Program…` with nothing else to fail, so this is where that fails.
 *
 * Asserting the extensions too: they are what tells the two modes apart in the dialog, and
 * [Exporter.getDefaultFileExtension] being final is the reason there are two exporters at all.
 */
@Tag("integration")
class ExporterDiscoveryIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun bothExportersAreDiscovered() {
        ClassSearcher.getInstances(Exporter::class.java)
            .filterIsInstance<StabsRenderExporter>()
            .associate { it.name to it.defaultFileExtension } mustBe
            mapOf("Stabs Decompilation" to "decomp", "Stabs Source Skeleton" to "skeleton")
    }
}
