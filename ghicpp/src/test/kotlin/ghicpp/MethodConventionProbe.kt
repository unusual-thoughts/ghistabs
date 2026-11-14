package ghicpp

import ghicpp.MemberAttrs.Companion.isPlacedByClassPass
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.program.model.listing.Function
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghidrakt.*
import ghidrakt.test.TestBinaries
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import java.io.File

/** Each stripped fixture through the whole analysis: how its methods take `this`. */
@Tag("probe")
class MethodConventionProbe : AbstractGhidraHeadlessIntegrationTest() {
    @ParameterizedTest
    @CsvSource(
        "features/hello_msvc.exe, windows",
        "features/hello_msvc_clang.exe, windows",
        "features/hello_elf_gcc12_stripped, gcc",
        "features/hello_gcc421_stripped.exe, gcc",
        "crypto_mi_test_gcc421_stripped.exe, gcc",
        "xmltest_gcc421_stripped.exe, gcc",
        "locale_test_customlibstdcxx_stripped.exe, gcc",
    )
    fun dump(name: String, compiler: String) {
        val only = System.getenv("PROBE_FIXTURE")
        assumeTrue(only == null || name.contains(only))
        val file = TestBinaries.file(name)
        loadProgram(file, compiler).use { loaded ->
            val program = loaded.program
            val mgr = AutoAnalysisManager.getAnalysisManager(program)
            mgr.initializeOptions()
            mgr.reAnalyzeAll(null)
            program.runTransaction("auto-analyze") {
                mgr.startAnalysis(TaskMonitor.DUMMY)
                mgr.waitForAnalysis(null, TaskMonitor.DUMMY)
            }
            val edx = program.language.getRegister("EDX")
            val methods = program.functionManager.getFunctions(true).filter {
                it.isMethod && !it.isExternal &&
                    !it.isThunk
            }
            fun Function.frozen() = hasCustomVariableStorage() && parameters.any { it.name == Function.THIS_PARAM_NAME }
            fun Function.fastNoEdx() = callingConventionName == "__fastcall" &&
                (edx == null || parameters.none { it.register?.baseRegister == edx })
            fun Function.autoThis() =
                parameters.firstOrNull()?.let { it.isAutoParameter && it.name == Function.THIS_PARAM_NAME } == true
            val placed = methods.filter { f -> program.isPlacedByClassPass(f) }
            val out = File("build/test-output/method-conventions/${file.name}.txt")
            out.parentFile.mkdirs()
            out.bufferedWriter().use { w ->
                for ((label, set) in listOf("all methods" to methods, "placed by a class pass" to placed)) {
                    w.write("== $label: ${set.size}\n")
                    w.write("  conventions: ${set.groupingBy { it.callingConventionName }.eachCount().toSortedMap()}\n")
                    w.write("  auto this: ${set.count { it.autoThis() }}\n")
                    w.write("  custom storage: ${set.count { it.hasCustomVariableStorage() }}\n")
                    w.write("  frozen (custom storage, explicit this): ${set.count { it.frozen() }}\n")
                    w.write("  __fastcall with nothing in EDX: ${set.count { it.fastNoEdx() }}\n")
                }
                w.write("\n")
                for (f in methods.sortedBy { it.entryPoint }) {
                    val flags = listOfNotNull(
                        "placed".takeIf { f in placed },
                        "custom".takeIf { f.hasCustomVariableStorage() },
                        "frozen".takeIf { f.frozen() },
                        "fastNoEdx".takeIf { f.fastNoEdx() },
                        "autoThis".takeIf { f.autoThis() },
                    )
                    w.write(
                        "${f.entryPoint} ${f.getName(
                            true,
                        )} ${f.callingConventionName} $flags | ${f.getPrototypeString(false, false)}\n",
                    )
                }
            }
        }
    }
}
