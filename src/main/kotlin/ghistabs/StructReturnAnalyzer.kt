package ghistabs

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.SpecExtension
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.data.Composite
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor

const val STRUCT_RETURN_ANALYZER_NAME = "Struct-return ABI (x86 gcc)"

/** Conventions this analyzer derives from, e.g. `__thiscall` → `__thiscall_memret`. */
val CORRECTABLE_CONVENTIONS = setOf("__cdecl", "__thiscall")

/** Which way round the epilogue says the cspec has a function's aggregate return. */
enum class Correction(val suffix: String, internal val outputRules: String) {
    /** Aggregates go back through a caller-allocated pointer; scalars still use the pentries. */
    TO_MEMORY(
        "_memret",
        """
        <rule><datatype name="struct"/><hidden_return/></rule>
        <rule><datatype name="union"/><hidden_return/></rule>
        """,
    ),

    /** No rule at all, so aggregates fall through to the EAX / EDX:EAX pentries. */
    TO_REGISTER("_regret", ""),
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
        // After the Stabs Importer (LOW), which sets the composite return types this reads.
        priority = AnalysisPriority.LOW_PRIORITY.after()
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
        val xml = conventionXml(base, fix)
        SpecExtension(program).run {
            if (SpecExtension.getCompilerSpecExtension(program, testExtensionDocument(xml)) == null) {
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
        f.localVariables.filter { it.name in RESERVED_PARAM_NAMES }.forEach { f.removeVariable(it) }
        f.setCallingConvention(convention)
        true
    }.getOrElse {
        log?.appendMsg(STRUCT_RETURN_ANALYZER_NAME, "failed on ${f.name} @ ${f.entryPoint}: ${it.message}")
        false
    }

    private companion object {
        val RESERVED_PARAM_NAMES = setOf("this", "__return_storage_ptr__")
    }
}

/**
 * x86gcc's `__cdecl`/`__thiscall` body — they are identical bar the aggregate rule — with [fix]'s
 * rules spliced into the output. `hasthis` must be explicit: auto-`this` is otherwise keyed off the
 * literal model name `__thiscall` (PrototypeModel ~line 647), so a derived name would lose it.
 */
private fun conventionXml(base: String, fix: Correction) =
    """
    <prototype name="${fix.conventionFor(base)}" extrapop="4" stackshift="4" hasthis="${base == "__thiscall"}">
      <input>
        <pentry minsize="1" maxsize="500" align="4"><addr offset="4" space="stack"/></pentry>
      </input>
      <output killedbycall="true">
        <pentry minsize="4" maxsize="10" metatype="float" extension="float"><register name="ST0"/></pentry>
        <pentry minsize="1" maxsize="4"><register name="EAX"/></pentry>
        <pentry minsize="5" maxsize="8"><addr space="join" piece1="EDX" piece2="EAX"/></pentry>
        ${fix.outputRules.trim()}
      </output>
      <unaffected>
        <register name="ESP"/><register name="EBP"/><register name="ESI"/>
        <register name="EDI"/><register name="EBX"/>
      </unaffected>
      <killedbycall>
        <register name="ECX"/><register name="EDX"/><register name="ST0"/><register name="ST1"/>
      </killedbycall>
      <likelytrash><register name="EAX"/></likelytrash>
    </prototype>
    """.trimIndent()
