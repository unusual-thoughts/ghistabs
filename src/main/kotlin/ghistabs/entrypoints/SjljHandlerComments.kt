package ghistabs.entrypoints

import ghidra.program.model.address.Address
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.program.model.scalar.Scalar
import ghidra.util.task.TaskMonitor
import ghistabs.Demangler
import ghistabs.cpp.eh.SjljAbi
import ghistabs.cpp.eh.SjljLsda
import ghistabs.pointerAt

/**
 * What a registering function's handlers catch, read from its LSDA into comments, as Ghidra's
 * `GCC Exception Handlers` analyzer comments the try and catch ranges of a DWARF one. SJLJ has no
 * ranges: before each call that may throw, gcc stores into `fc.call_site` the index of the call-site
 * record that covers it, so each store gets a pre comment naming its landing pad and what it does:
 * ```
 * SJLJ call site 2, landing pad 1: catch (CryptoPP::InvalidArgument), cleanup
 * ```
 * and the receiver, which dispatches on the landing pad index, one line per pad. The decompiler
 * shows pre comments, so each lands above the protected call's `fc.call_site = 2;`.
 */
internal object SjljHandlerComments {
    const val PREFIX = "SJLJ call site"

    /** Offset of `call_site` in the context. */
    private const val CALL_SITE_OFFSET = 4

    fun comment(program: Program, reg: SjljLsdaAnalyzer.Registration, lsda: SjljLsda, monitor: TaskMonitor) {
        val fn = program.functionManager.getFunctionContaining(reg.store) ?: return
        val slot = (SjljContextAnalyzer.lsdaDisplacement(program, reg) ?: return) -
            SjljAbi.LSDA_OFFSET + CALL_SITE_OFFSET
        for (insn in program.listing.getInstructions(fn.body, true)) {
            monitor.checkCancelled()
            val text = callSiteStored(insn, slot)?.let { describe(program, lsda, it) } ?: continue
            setOwn(program, insn.address, text)
        }
        reg.resume?.let { commentReceiver(program, it, lsda) }
    }

    /** The index [insn] stores, if it is a `movl $index, slot(%ebp)`. */
    private fun callSiteStored(insn: Instruction, slot: Long): Long? {
        if (insn.mnemonicString != "MOV" || insn.numOperands != 2) return null
        val dest = insn.getOpObjects(0)
        if (dest.none { it is Register && it.name == "EBP" }) return null
        if (dest.filterIsInstance<Scalar>().singleOrNull()?.signedValue != slot) return null
        return insn.getScalar(1)?.signedValue
    }

    /** One line per landing pad under the receiver's own comment, [SjljLsdaAnalyzer.layResume]'s. */
    private fun commentReceiver(program: Program, receiver: Address, lsda: SjljLsda) {
        val pads = lsda.callSites.groupBy { it.landingPad }.toSortedMap().map { (pad, sites) ->
            "landing pad $pad: " + sites.map { handlers(program, lsda, it) }.distinct().joinToString(" | ")
        }
        val listing = program.listing
        val head = listing.getComment(CommentType.PRE, receiver)?.lineSequence()?.first() ?: return
        listing.setComment(receiver, CommentType.PRE, (listOf(head) + pads).joinToString("\n"))
    }

    /**
     * What the call-site [index] gcc stores selects, as `__gxx_personality_sj0` reads it: -1 no
     * handler (nothing to say), 0 terminate, N the Nth record.
     */
    private fun describe(program: Program, lsda: SjljLsda, index: Long): String? = when {
        index < 0 -> null

        index == 0L -> "$PREFIX 0: terminate if anything throws"

        else -> lsda.callSites.getOrNull((index - 1).toInt())?.let {
            "$PREFIX $index, landing pad ${it.landingPad}: ${handlers(program, lsda, it)}"
        }
    }

    private fun handlers(program: Program, lsda: SjljLsda, site: SjljLsda.CallSite): String {
        val filters = lsda.filters(site)
        if (filters.isEmpty()) return "cleanup"
        return filters.joinToString(", ") { filter ->
            when {
                filter > 0 -> "catch (${typeName(program, lsda, filter) ?: "..."})"

                filter == 0L -> "cleanup"

                else -> "throw (" + lsda.specs[filter].orEmpty().joinToString(", ") {
                    typeName(program, lsda, it) ?: "?"
                } + ")"
            }
        }
    }

    /** The type type table entry [n] names, by its typeinfo's symbol; null for `catch (...)`. */
    private fun typeName(program: Program, lsda: SjljLsda, n: Long): String? {
        val at = lsda.typeAt(n, program.defaultPointerSize) ?: return null
        val typeinfo = program.pointerAt(at)?.takeIf { it.offset != 0L } ?: return null
        val symbol = program.symbolTable.getPrimarySymbol(typeinfo) ?: return "$typeinfo"
        if (symbol.name == TYPEINFO) return symbol.parentNamespace.getName(true)
        val demangled = Demangler.of(symbol.name)
        return demangled?.takeIf { it.name == TYPEINFO }?.namespace?.namespaceString ?: symbol.getName(true)
    }

    private const val TYPEINFO = "typeinfo"

    /** Comment [at], unless someone else's comment is there. */
    private fun setOwn(program: Program, at: Address, text: String) {
        val existing = program.listing.getComment(CommentType.PRE, at)
        if (existing == null || existing.startsWith(PREFIX)) program.listing.setComment(at, CommentType.PRE, text)
    }
}
