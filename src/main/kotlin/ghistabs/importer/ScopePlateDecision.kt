package ghistabs.importer

/**
 * Pure decision logic for emitting Stabs scope-locals plate comments.
 * Suppresses empty scope comments (when a scope contains no locals).
 */
object ScopePlateDecision {
    /**
     * Determines whether a Stabs scope-locals plate comment should be emitted for a given scope.
     *
     * @param localCount The number of locals in the scope.
     * @return true if localCount > 0, false otherwise.
     */
    fun shouldEmitScopePlate(localCount: Int): Boolean = localCount > 0
}
