package ghistabs.importer

object ApplyErrorBucket {
    fun bucket(throwable: Throwable): String {
        val msg = throwable.message.orEmpty()
        return when {
            "entrypoint" in msg || "not found" in msg -> "entrypoint-mismatch"
            "parameter" in msg.lowercase() -> "parameter-mismatch"
            throwable::class.qualifiedName == "ghidra.util.exception.InvalidInputException" -> "invalid-input"
            throwable::class.qualifiedName == "ghidra.util.exception.DuplicateNameException" -> "duplicate-name"
            else -> "other"
        }
    }
}
