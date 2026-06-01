package ghistabs.diag

object ApplyErrorBucket {
    fun bucket(throwable: Throwable): String {
        val msg = throwable.message.orEmpty().lowercase()
        return when {
            "entrypoint" in msg || "not found" in msg -> "entrypoint-mismatch"
            "parameter" in msg -> "parameter-mismatch"
            throwable::class.qualifiedName == "ghidra.util.exception.InvalidInputException" -> "invalid-input"
            throwable::class.qualifiedName == "ghidra.util.exception.DuplicateNameException" -> "duplicate-name"
            else -> "other"
        }
    }
}
