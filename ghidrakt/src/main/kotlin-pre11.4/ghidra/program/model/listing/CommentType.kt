package ghidra.program.model.listing

/**
 * The comment kinds 11.4 turned into an enum. Before it they are the `CodeUnit` ints that
 * `Listing.setComment`/`getComment` take, and the enum was declared in that same order — its
 * constants are documented as the old ordinals — so these values are the enum's, spelled as ints.
 */
object CommentType {
    const val EOL = CodeUnit.EOL_COMMENT
    const val PRE = CodeUnit.PRE_COMMENT
    const val POST = CodeUnit.POST_COMMENT
    const val PLATE = CodeUnit.PLATE_COMMENT
    const val REPEATABLE = CodeUnit.REPEATABLE_COMMENT
}
