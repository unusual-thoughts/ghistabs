package ghistabs.importer

import ghidra.app.util.demangler.DemangledDataType
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.TypeDef
import ghidra.program.model.data.Undefined4DataType
import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.listing.Function
import ghistabs.diagnose.DiagnosticSink

// The signature rules both apply passes share: SymbolApplier.applyAllFunctions for every function the
// stabs define, then ClassApplier for each member it reparents into its class.

/**
 * The convention [this] needs, or null when its own already fits: `__thiscall` when it [takesThis] and
 * the cspec has one, the default when it takes none but its convention passes one. Ghidra's demangler
 * can't tell: Itanium mangling spells a static member like an instance one, so both come out
 * `__thiscall`, and a variadic member gets MSVC's `__stdcall`, which passes no `this` at all.
 */
fun Function.conventionFor(takesThis: Boolean): String? {
    val passesThis = callingConvention?.hasThisPointer() == true
    val cspec = program.compilerSpec
    return when {
        takesThis && !passesThis ->
            CompilerSpec.CALLING_CONVENTION_thiscall.takeIf { cspec.getCallingConvention(it) != null }

        !takesThis && passesThis -> cspec.defaultCallingConvention.name

        else -> null
    }
}

/**
 * [this] as the type of a parameter the stabs don't type, or null when the demangler has none to give.
 * A class it can't find by name comes back as an empty `/Demangler` stand-in, and anything else it
 * can't find, an enum included, as a typedef of the 1-byte `undefined`. Neither is the parameter's
 * size, and applying either loses the parameter's name and moves every slot after it: typing gcc 12
 * `xmltest`'s `XMLDocument::SetError(XMLError error, int, const char* format, ...)`'s `error` so
 * cost `format` its `char*`.
 */
fun DemangledDataType.parameterType(dtm: DataTypeManager): DataType? = runCatching { getDataType(dtm) }
    .getOrNull()
    ?.takeUnless { it.isNotYetDefined || it.isZeroLength || it.withoutTypedefs() == DataType.DEFAULT }

/** [t]'s [parameterType], or `undefined4` with a [category] degradation against [degrades]. */
fun DiagnosticSink.parameterTypeOrUndefined(
    t: DemangledDataType,
    dtm: DataTypeManager,
    category: String,
    degrades: String,
): DataType = t.parameterType(dtm)
    ?: Undefined4DataType.dataType.also { degradation(category, degrades, "demangler gave no type for $t") }

/**
 * Which of [declared] slots each of [stabs] fills, as the stab index per slot (null for a slot no stab
 * fills). gcc emits no N_PSYM for an unnamed parameter, which can sit anywhere: `operator new(size_t,
 * void* __p)`'s is at the head. So the stabs go, in order, where their types agree best with the
 * declared ones, and a gap falls on the tail when nothing tells the slots apart, as unnamed parameters
 * mostly do. A stab whose type is null agrees with nothing. Null when [declared] has no room for the
 * stabs.
 */
internal fun alignToDeclared(stabs: List<DataType?>, declared: List<Lazy<DataType?>>): List<Int?>? {
    val n = stabs.size
    val m = declared.size
    if (m < n) return null
    if (m == n) return stabs.indices.toList()
    fun score(i: Int, j: Int): Int {
        val stab = stabs[i] ?: return 0
        val decl = declared[j].value ?: return 0
        return when {
            stab.agreesWith(decl) -> 2
            stab.length == decl.length -> 1
            else -> 0
        }
    }
    // best[i][j]: the highest total for the first i stabs in the first j slots.
    val best = Array(n + 1) { i -> IntArray(m + 1) { j -> if (i == 0) 0 else Int.MIN_VALUE / 2 } }
    for (i in 1..n) {
        for (j in i..m) best[i][j] = maxOf(best[i][j - 1], best[i - 1][j - 1] + score(i - 1, j - 1))
    }
    // Walk back from the last slot, leaving it empty whenever that costs nothing.
    val slots = arrayOfNulls<Int>(m)
    var i = n
    var j = m
    while (i > 0) {
        if (best[i][j - 1] != best[i][j]) slots[j - 1] = --i
        j--
    }
    return slots.toList()
}

/** The same type up to typedefs, at the top and under pointers. */
private fun DataType.agreesWith(other: DataType): Boolean {
    val a = withoutTypedefs()
    val b = other.withoutTypedefs()
    if (a is Pointer && b is Pointer) {
        val pa = a.dataType
        val pb = b.dataType
        return if (pa == null || pb == null) pa == pb else pa.agreesWith(pb)
    }
    return a.isEquivalent(b) || a.name == b.name
}

private fun DataType.withoutTypedefs(): DataType = generateSequence(this) { (it as? TypeDef)?.dataType }.last()
