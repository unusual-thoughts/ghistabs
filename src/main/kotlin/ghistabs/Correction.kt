package ghistabs

/**
 * Which way round the epilogue says the cspec has a function's aggregate return. Each names the prototype
 * model `StructReturnAnalyzer` derives from a stock one, `<base><suffix>`, which Ghidra then prints like
 * any convention and the render strips like one.
 */
enum class Correction(val suffix: String) {
    /** Aggregates go back through a caller-allocated pointer; scalars still use the pentries. */
    TO_MEMORY("_memret"),

    /** No aggregate rule at all, so they fall through to the EAX / EDX:EAX pentries. */
    TO_REGISTER("_regret"),
    ;

    fun conventionFor(base: String) = "$base$suffix"
}
