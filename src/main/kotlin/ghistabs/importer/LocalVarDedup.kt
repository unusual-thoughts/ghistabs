package ghistabs.importer

sealed class SkipReason {
    object DuplicateParamName : SkipReason()

    object DuplicateLocalName : SkipReason()
}

object LocalVarDedup {
    fun shouldSkipLocal(
        name: String,
        existingParamNames: Set<String>,
        existingLocalNames: Set<String>,
    ): SkipReason? =
        when {
            name in existingParamNames -> SkipReason.DuplicateParamName
            name in existingLocalNames -> SkipReason.DuplicateLocalName
            else -> null
        }
}
