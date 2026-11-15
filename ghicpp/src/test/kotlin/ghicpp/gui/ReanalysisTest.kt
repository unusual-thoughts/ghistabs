package ghicpp.gui

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalyzerType
import ghidrakt.diagnose.capturingReports
import ghidrakt.diagnose.report
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

class ReanalysisTest {
    private class Named(name: String) : AbstractAnalyzer(name, "", AnalyzerType.BYTE_ANALYZER)

    @Test
    fun `what analyzers report inside capturingReports is kept, in order, and only there`() {
        val a = Named("A")
        a.report("before")
        val (value, inner) = capturingReports {
            a.report("one")
            val (_, nested) = capturingReports { Named("B").report("two") }
            nested mustBe listOf("B: two")
            a.report("three")
            42
        }
        value mustBe 42
        inner mustBe listOf("A: one", "A: three")
        capturingReports { }.second mustBe emptyList()
    }

    @Test
    fun `the summary says what each analyzer did, or that it had nothing to change`() {
        Reanalysis(
            ran = listOf("Itanium typeinfo", "Itanium RTTI classes"),
            reports = listOf("Itanium RTTI classes: 7 class(es)"),
            problems = "",
        ).summary() mustBe "Itanium typeinfo: nothing to change\nItanium RTTI classes: 7 class(es)"
    }

    @Test
    fun `the summary ends with a cancel, a failure and the warnings, at most twenty of them`() {
        val done = Reanalysis(
            ran = listOf("A"),
            reports = emptyList(),
            problems = (1..22).joinToString("\n") { "w$it" },
            cancelled = true,
            failure = IllegalStateException("boom"),
        )
        done.isTrouble mustBe true
        done.summary().lines() mustBe listOf(
            "A: nothing to change",
            "",
            "Cancelled: what ran before then is kept.",
            "",
            "Failed: boom",
            "",
            "Warnings (22):",
        ) + (1..20).map { "  w$it" } + "  … 2 more in the log"
    }

    @Test
    fun `with no analyzer to run, the summary says why`() {
        Reanalysis(emptyList(), emptyList(), "").summary() mustBe
            "No class analyzer applies to this program, or each is off in Analysis Options."
    }
}
