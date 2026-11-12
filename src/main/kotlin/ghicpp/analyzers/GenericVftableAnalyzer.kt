package ghicpp.analyzers

import ghicpp.VfptrModel
import ghicpp.recover.*
import ghicpp.recover.ClassPass.Companion.FILL_ARRAYS
import ghicpp.recover.ClassPass.Companion.INLINED_CONSTRUCTORS
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.framework.options.Options
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghidrakt.BoolOption
import ghidrakt.analyzerOptions
import ghidrakt.diagnose.AnalysisProbe
import ghidrakt.diagnose.MessageLogSink
import ghidrakt.diagnose.report
import ghidrakt.get
import ghidrakt.register

/**
 * Seed vftables where no RTTI says where they are, absent or in a format no analyzer reads, off the tables of
 * pointers to functions that code takes the address of ([GenericVftableFinder]), then recover their classes as
 * the RTTI class analyzers do ([ClassPass] over a [PlainVtableParser]): each slot's target made a function and
 * moved into its class, the constructors and destructors found by their vtable stores, the class sized and
 * its struct filled, and the classes with no vtable that their constructors build members of
 * ([MemberObjectPass]). Then guess the class of the non-virtual methods off the objects passed to them
 * ([MethodClassPass]).
 *
 * Off by default: its tables are a guess off their shape. It reads references, so run it once most of the
 * program is disassembled and its operand references are marked, and again after: the code its slots led to
 * may refer to tables it couldn't see before.
 */
class GenericVftableAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Find vtables without RTTI, as tables of function pointers code takes the address of, give each a " +
            "class, and move its virtual functions, constructors and destructors into it",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        // After the class analyzers whose RTTI claims its tables first, and the method class guesses off those.
        priority = AnalysisPriority.LOW_PRIORITY.after().after().after().after().after()
        setDefaultEnablement(false)
        setSupportsOneTimeAnalysis()
    }

    override fun registerOptions(options: Options, program: Program) =
        options.register(VfptrModel.OPTION, FILL_ARRAYS, INLINED_CONSTRUCTORS, MEMBER_OBJECTS)

    override fun canAnalyze(program: Program) = program.compilerSpec.callingConventions.any { it.hasThisPointer() }

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        val sink = AnalysisProbe.sinkFor(program, MessageLogSink(log, originator = NAME))
        val seeded = GenericVftableFinder(program, sink = sink).seed(monitor)
        val options = program.analyzerOptions(NAME)
        val pass = ClassPass(program, PlainVtableParser(program, sink), sink, options)
        val result = pass.run(monitor)
        val members = result.found?.takeIf { options[MEMBER_OBJECTS] }
            ?.let { MemberObjectPass(program, sink, pass.fillArrays).run(it, monitor) } ?: 0
        val guessed = MethodClassPass(program, sink).run(monitor)
        report(
            "$seeded vftable(s) seeded; ${result.classes} class(es), ${result.owned} virtual function(s) owned, " +
                "${result.structors} constructor(s) and destructor(s) named, $members member object class(es), " +
                "$guessed method class(es) guessed",
        )
        return true
    }

    companion object {
        const val NAME = "Vftables from pointer tables"

        val MEMBER_OBJECTS = BoolOption(
            "Classes of member objects",
            "Give a class to each member a constructor builds at an offset into this with a function that " +
                "stores no vtable, and lay it in the class holding it",
            true,
        )
    }
}
