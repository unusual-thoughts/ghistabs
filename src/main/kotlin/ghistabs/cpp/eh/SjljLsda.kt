package ghistabs.cpp.eh

import ghidra.program.model.address.Address
import ghidra.program.model.data.ByteDataType
import ghidra.program.model.data.DataType
import ghidra.program.model.data.SignedLeb128DataType
import ghidra.program.model.data.UnsignedLeb128DataType
import ghidra.program.model.listing.Program
import ghidra.program.model.scalar.Scalar
import ghistabs.*

/**
 * One gcc SJLJ LSDA (`.gcc_except_table` entry), parsed as `__gxx_personality_sj0` reads it:
 * libstdc++'s `parse_lsda_header` and its `__USING_SJLJ_EXCEPTIONS__` call-site walk.
 *
 * ```
 * u8      lpstart encoding       always omitted (0xff): SJLJ landing pads are dispatch indices
 * u8      ttype encoding         0xff (no type table) or absptr
 * uleb128 ttype offset           only with a type table; the type table's base is the byte after it plus this
 * u8      call-site encoding     uleb128
 * uleb128 call-site table length
 *   { uleb128 landing pad, uleb128 action }…   the call-site index the function stores before a call picks one
 * action table                   { sleb128 filter, sleb128 next }…, reached from the call sites' actions
 * type table                     pointers to typeinfo, entry N at base - N * pointer size, null for `catch (...)`
 * exception specs                uleb128 type indices from base, each list ended by 0
 * ```
 *
 * A filter above 0 catches type table entry N, 0 is a cleanup, and one below 0 is an exception
 * specification whose list starts at base + (-filter - 1). An action's next is relative to its own
 * next field, 0 ending the chain. Between the action table and the type table gcc pads to the type
 * table's alignment.
 *
 * Every field is placed by its address; [start] is the LSDA's first byte.
 */
class SjljLsda private constructor(
    val start: Address,
    val items: List<Item>,
    val callSites: List<CallSite>,
    val actions: List<Action>,
    /** How many type table entries a filter or exception spec reaches. */
    val typeCount: Int,
) {
    enum class Kind { ENCODING, ULEB128, SLEB128, POINTER, ALIGNMENT }

    /** One field to lay, [length] bytes at [at], with what it holds. */
    data class Item(val at: Address, val length: Int, val kind: Kind, val comment: String)

    data class CallSite(val landingPad: Long, val action: Long)

    data class Action(val at: Address, val filter: Long, val next: Long)

    /** Bytes from the LSDA's start to the end of its last field. */
    val size get() = items.maxOf { it.at + it.length } - start

    private class Malformed : RuntimeException()

    private class Cursor(val program: Program, var at: Address) {
        private fun scalar(dt: DataType): Scalar = at.let { here ->
            at += program.lengthAt(here, dt) ?: throw Malformed()
            program.valueAt<Scalar>(here, dt) ?: throw Malformed()
        }

        fun u8() = scalar(ByteDataType.dataType).unsignedValue.toInt()

        fun leb(signed: Boolean): Long = if (signed) {
            scalar(SignedLeb128DataType.dataType).signedValue
        } else {
            scalar(UnsignedLeb128DataType.dataType).unsignedValue
        }

        fun isNull(): Boolean {
            val value = program.pointerAt(at) ?: throw Malformed()
            at += program.defaultPointerSize
            return value.offset == 0L
        }
    }

    companion object {
        const val OMIT = 0xff
        const val ABSPTR = 0x00
        const val ULEB128 = 0x01

        // Bounds that keep a misidentified LSDA from walking off into memory: gcc's largest in the
        // corpus has a few dozen call sites and actions, and pads at most one pointer's worth.
        private const val MAX_TABLE = 0x4000L
        private const val MAX_PAD = 16L

        /** The LSDA at [at], or null if its bytes are not one. */
        fun parse(program: Program, at: Address): SjljLsda? = try {
            Parser(Cursor(program, at), program.defaultPointerSize).parse()
        } catch (_: Malformed) {
            null
        }
    }

    private class Parser(val c: Cursor, val pointerSize: Int) {
        val start = c.at
        val items = mutableListOf<Item>()

        /** Just past the last action record: where the type table's padding starts. */
        lateinit var actionEnd: Address

        fun item(at: Address, kind: Kind, comment: String) {
            items += Item(at, (c.at - at).toInt(), kind, comment)
        }

        fun encoding(comment: String) = c.at.let { at ->
            c.u8().also { item(at, Kind.ENCODING, comment) }
        }

        fun leb(signed: Boolean, comment: String) = c.at.let { at ->
            c.leb(signed).also { item(at, if (signed) Kind.SLEB128 else Kind.ULEB128, comment) }
        }

        fun expect(ok: Boolean) {
            if (!ok) throw Malformed()
        }

        fun parse(): SjljLsda {
            expect(encoding("(LSDA) LPStart Encoding") == OMIT)
            val base = when (encoding("(LSDA) TType Encoding")) {
                OMIT -> null
                ABSPTR -> leb(false, "(LSDA) TType Offset").also { expect(it in 1..MAX_TABLE) }.let { c.at + it }
                else -> throw Malformed()
            }
            expect(encoding("(LSDA) Call Site Table Encoding") == ULEB128)
            val length = leb(false, "(LSDA) Call Site Table Length")
            expect(length in 1..MAX_TABLE)
            val actionTable = c.at + length

            val callSites = callSites(actionTable)
            val actions = actions(actionTable, callSites, base)
            expect(base != null || actions.all { it.filter == 0L })
            val typeCount = if (base == null) 0 else types(base, actions)
            return SjljLsda(start, items.distinctBy { it.at }.sortedBy { it.at }, callSites, actions, typeCount)
        }

        fun callSites(actionTable: Address) = buildList {
            while (c.at < actionTable) {
                val n = size + 1
                val pad = leb(false, "(LSDA Call Site $n) Landing Pad Index")
                val action = leb(false, "(LSDA Call Site $n) Action Table Offset")
                add(CallSite(pad, action))
            }
            expect(c.at == actionTable)
        }

        /** The action records [callSites] reach, chains followed, in address order. */
        fun actions(actionTable: Address, callSites: List<CallSite>, base: Address?): List<Action> {
            val actions = sortedMapOf<Address, Action>()
            actionEnd = actionTable
            val pending = ArrayDeque(callSites.filter { it.action != 0L }.map { actionTable + it.action - 1 })
            while (pending.isNotEmpty()) {
                val at = pending.removeFirst()
                if (at in actions) continue
                expect(at >= actionTable && at - actionTable < MAX_TABLE && (base == null || at < base))
                c.at = at
                val filter = leb(true, "(LSDA Action) Type Filter")
                expect(-filter <= MAX_TABLE)
                val nextAt = c.at
                val next = leb(true, "(LSDA Action) Next-Action Reference")
                actions[at] = Action(at, filter, next)
                actionEnd = maxOf(actionEnd, c.at)
                if (next != 0L) pending += nextAt + next
            }
            return actions.values.toList()
        }

        /**
         * The exception spec lists at [base] and the type table below it, with the padding between it
         * and the action table; returns how many entries the filters and specs reach.
         */
        fun types(base: Address, actions: List<Action>): Int {
            var typeCount = actions.maxOfOrNull { it.filter }?.coerceAtLeast(0L) ?: 0L
            for (spec in actions.filter { it.filter < 0 }.map { base - it.filter - 1 }.distinct()) {
                c.at = spec
                do {
                    val index = leb(false, "(LSDA Exception Spec) Type Index")
                    typeCount = maxOf(typeCount, index)
                } while (index != 0L)
            }
            expect(typeCount <= MAX_TABLE)
            val types = base - typeCount * pointerSize
            expect(types >= actionEnd && types - actionEnd < MAX_PAD)
            if (types > actionEnd) {
                items += Item(actionEnd, (types - actionEnd).toInt(), Kind.ALIGNMENT, "(LSDA) Type Table Alignment")
            }
            for (n in typeCount downTo 1) {
                c.at = base - n * pointerSize
                val what = if (c.isNull()) "catch (...)" else "Type Reference"
                items += Item(base - n * pointerSize, pointerSize, Kind.POINTER, "(LSDA Type $n) $what")
            }
            return typeCount.toInt()
        }
    }
}
