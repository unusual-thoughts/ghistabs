package ghistabs

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.SpecExtension
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.data.Composite
import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.XmlEncode
import ghidra.util.task.TaskMonitor
import org.w3c.dom.Element
import org.xml.sax.InputSource
import java.io.StringReader
import java.io.StringWriter
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.OutputKeys
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult

const val STRUCT_RETURN_ANALYZER_NAME = "Struct-return ABI (x86 gcc)"

/** Conventions this analyzer derives from, e.g. `__thiscall` → `__thiscall_memret`. */
val CORRECTABLE_CONVENTIONS = setOf(CompilerSpec.CALLING_CONVENTION_cdecl, CompilerSpec.CALLING_CONVENTION_thiscall)

/** Which way round the epilogue says the cspec has a function's aggregate return. */
enum class Correction(val suffix: String) {
    /** Aggregates go back through a caller-allocated pointer; scalars still use the pentries. */
    TO_MEMORY("_memret"),

    /** No aggregate rule at all, so they fall through to the EAX / EDX:EAX pentries. */
    TO_REGISTER("_regret"),
    ;

    fun conventionFor(base: String) = "$base$suffix"
}

/**
 * gcc/MinGW i386 returns a class in memory — through a caller-allocated hidden pointer — whenever it
 * is non-trivial for calls (`std::string`, `list`, `vector`), *regardless of size*. Trivial
 * aggregates of 1/2/4/8 bytes really do come back in AL/AX/EAX/EDX:EAX, since mingw defaults to
 * `-freg-struct-return`. No cspec rule can express "non-trivial for calls", so x86gcc.cspec is wrong
 * in both directions at once: `__thiscall` register-returns a 4-byte `std::string` that is really an
 * sret, and `__cdecl` force-indirects a small POD that really comes back in EDX:EAX.
 *
 * The codegen settles it: the callee pops the hidden pointer, so a memory return ends `RET 0x4` while
 * a register return ends bare `RET`. Ghidra's built-in "X86 Function Callee Purge" analyzer already
 * reads that off the terminator into [Function.getStackPurgeSize] at FUNCTION_ANALYSIS priority —
 * long before this pass — and then never connects it to the return-storage decision. Making that
 * connection, in whichever direction disagrees, is all this analyzer does.
 *
 * Corrections are expressed as *calling conventions*, not custom storage: a derived model is installed
 * as a program spec extension (the mechanism Rust and Objective-C support already use) and matching
 * functions are reassigned to it. Ghidra then lays out the hidden pointer and `this` itself, keeps
 * them in sync if the signature changes later, and shows the correction as a named convention a human
 * can see and undo. Deriving the model from the function's *own* convention is also what keeps this
 * honest if the cspec changes underneath us — including the day `__thiscall` gains the `<hidden_return/>`
 * rule that `__cdecl` got in GP-5183, which would otherwise silently strand every POD return.
 *
 * Independent of stabs; keyed only on the x86:LE:32 gcc ABI (on SysV x86-64 small PODs really do
 * return in registers, so this must not run there).
 */
class StructReturnAnalyzer :
    AbstractAnalyzer(
        STRUCT_RETURN_ANALYZER_NAME,
        "Reconcile by-value struct/class return storage with the callee's stack purge.",
        AnalyzerType.FUNCTION_ANALYZER,
    ) {
    init {
        // After the Stabs Importer (LOW), which sets the composite return types this reads, and
        // after [ThisParamAnalyzer], whose repair is what makes a frozen method visible here at all
        // ([correctionFor] skips custom storage).
        priority = AnalysisPriority.LOW_PRIORITY.after().after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program?) = program?.run {
        language.processor.toString() == "x86" &&
            !language.isBigEndian &&
            defaultPointerSize == 4 &&
            compilerSpec.compilerSpecID.idAsString == "gcc"
    } ?: false

    override fun added(program: Program?, set: AddressSetView?, monitor: TaskMonitor?, log: MessageLog?): Boolean {
        program ?: return false
        val work = program.functionManager.getFunctions(set, true).mapNotNull { f ->
            monitor?.checkCancelled()
            correctionFor(program, f)?.let { Triple(f, f.callingConventionName, it) }
        }
        if (work.isEmpty()) return true

        // Only install the models we are about to use, and only once each.
        val ready = work.mapTo(mutableSetOf()) { (_, base, fix) -> base to fix }
            .filterTo(mutableSetOf()) { (base, fix) -> install(program, base, fix, log) }

        val fixed = work.count { (f, base, fix) ->
            (base to fix) in ready && reassign(f, fix.conventionFor(base), log)
        }
        if (fixed > 0) log?.appendMsg(STRUCT_RETURN_ANALYZER_NAME, "corrected return storage on $fixed function(s)")
        return true
    }

    /**
     * A purge of one pointer means the callee popped a caller-allocated return slot; a purge of zero
     * on a caller-cleans convention means it did not. Either way, disagreement with the cspec's
     * forced-indirect decision is the whole signal.
     */
    private fun correctionFor(program: Program, f: Function) = when {
        f.isThunk || f.hasCustomVariableStorage() -> null
        // Not `dataType`: on a forced-indirect return that is already the hidden *pointer*.
        f.`return`.formalDataType !is Composite -> null
        f.callingConventionName !in CORRECTABLE_CONVENTIONS -> null
        f.stackPurgeSize == program.defaultPointerSize && !f.`return`.isForcedIndirect -> Correction.TO_MEMORY
        f.stackPurgeSize == 0 && f.`return`.isForcedIndirect -> Correction.TO_REGISTER
        else -> null
    }

    private fun install(program: Program, base: String, fix: Correction, log: MessageLog?): Boolean = runCatching {
        val xml = derivedConventionXml(program, base, fix)
        SpecExtension(program).run {
            if (testExtensionDocument(xml).installedIn(program) == null) {
                addReplaceCompilerSpecExtension(xml, TaskMonitor.DUMMY)
            }
        }
        true
    }.getOrElse {
        log?.appendMsg(STRUCT_RETURN_ANALYZER_NAME, "could not install ${fix.conventionFor(base)}: ${it.message}")
        false
    }

    private fun reassign(f: Function, convention: String, log: MessageLog?): Boolean = runCatching {
        // reparentMethod's explicit-`this` under __thiscall leaves a spurious local named `this`,
        // which collides with the auto-parameter the derived convention reinstates.
        f.localVariables.filter { it.collidesWithInjectedParameter }.forEach { f.removeVariable(it) }
        f.setCallingConvention(convention)
        true
    }.getOrElse {
        log?.appendMsg(STRUCT_RETURN_ANALYZER_NAME, "failed on ${f.name} @ ${f.entryPoint}: ${it.message}")
        false
    }
}

/**
 * The program's own [base] model, re-encoded and adjusted for [fix]. Derived rather than transcribed,
 * so a derived convention tracks whatever the installed cspec currently says — `<returnaddress>`,
 * `hasthis`, register sets, and any rule added to that prototype later all come along by construction.
 * [ghidra.program.model.lang.PrototypeModel.encode] emits exactly the grammar [SpecExtension] parses, rules included.
 *
 * Aggregate `<hidden_return/>` rules are dropped either way and re-added only for [Correction.TO_MEMORY]:
 * the model is assigned solely to functions whose purge already settled the question, so a size-filtered
 * rule in the base has nothing left to decide.
 */
private fun derivedConventionXml(program: Program, base: String, fix: Correction): String {
    val model = requireNotNull(program.compilerSpec.getCallingConvention(base)) { "no calling convention $base" }
    val encoded = XmlEncode().apply { model.encode(this, program.compilerSpec.pcodeInjectLibrary) }.toString()
    val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(InputSource(StringReader(encoded)))

    doc.documentElement.setAttribute("name", fix.conventionFor(base))
    val output = doc.documentElement.children("output").single()
    output.children("rule").filter { it.children("hidden_return").isNotEmpty() }.forEach(output::removeChild)
    if (fix == Correction.TO_MEMORY) {
        // struct and union are distinct metatypes to string2metatype, so neither covers the other.
        listOf("struct", "union").forEach { metatype ->
            output.appendChild(
                doc.createElement("rule").apply {
                    appendChild(doc.createElement("datatype").apply { setAttribute("name", metatype) })
                    appendChild(doc.createElement("hidden_return"))
                },
            )
        }
    }
    return StringWriter().also {
        TransformerFactory.newInstance().newTransformer().apply {
            setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes")
        }.transform(DOMSource(doc), StreamResult(it))
    }.toString()
}

private fun Element.children(tag: String) = childNodes.let { kids -> (0 until kids.length).map(kids::item) }
    .filterIsInstance<Element>().filter {
        it.tagName == tag
    }

/** The extension document already registered under this one's formal name, or null.  */
private fun SpecExtension.DocInfo.installedIn(program: Program) =
    SpecExtension.getCompilerSpecExtension(program, type, formalName)
