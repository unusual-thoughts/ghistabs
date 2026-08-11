package ghistabs.render

import ghidra.program.model.listing.Function

/** What a body lifted out of the member it was written in calls the object it was called on. */
const val SELF = "self"

/** Ghidra's name for the implicit object parameter it prints as an explicit one. */
const val THIS = "this"

/**
 * A Ghidra function's prototype as C++ text, assembled from the function rather than cut back out of
 * `FunctionSignature.prototypeString`.
 *
 * Ghidra builds that string as the return type's display name, the function's name, and each
 * parameter's `displayName name` — nothing our own assembly cannot restate — so putting it together
 * here loses nothing and lets the two things C++ does not admit be *left out* rather than found
 * again in the characters: [dropThis] omits the explicit `this` a member function is stored with,
 * [dropReturnType] the return type a constructor or destructor may not carry. A regex over the
 * rendered prototype had to find the parameter list by its parentheses, which a parameter that is
 * itself a function pointer breaks.
 *
 * [rename] spells each name — a wrapper turns a member's body into a free function, where `this` is
 * a keyword and a destructor's leading `~` is not a name at all.
 */
fun Function.prototype(
    dropThis: Boolean = false,
    dropReturnType: Boolean = false,
    rename: (String) -> String = { it },
): String {
    val kept = parameters.filterNot { dropThis && it.name == THIS }
    val params =
        kept.map { "${it.dataType.displayName} ${rename(it.name)}" } + if (hasVarArgs()) listOf("...") else listOf()
    // `(void)` only where the function truly takes nothing; dropping `this` off a nullary member
    // leaves an empty list, not a void one.
    val list = params.joinToString(", ").ifEmpty { if (parameters.isEmpty()) "void" else "" }
    // The *formal* return type, the one the signature carries: where the ABI returns a struct through
    // hidden storage, `getReturnType` is the pointer the caller passes and the formal type is the
    // struct the source declared.
    return (if (dropReturnType) "" else "${getReturn().formalDataType.displayName} ") + "${rename(name)}($list)"
}

/**
 * A name as a free function's wrapper must spell it: `this` is a C++ keyword and cannot be a
 * parameter, and a destructor's leading `~` is not a name at all once there is no class to destroy.
 */
fun asFree(name: String) = when {
    name == THIS -> SELF
    name.startsWith("~") -> "dtor_" + name.drop(1)
    else -> name
}
