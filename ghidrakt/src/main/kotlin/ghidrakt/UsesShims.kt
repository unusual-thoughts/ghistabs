package ghidrakt

/**
 * Marks a file whose only ghidrakt names are compat shims from a `kotlin-pre*` or `kotlin-since*` source set. Built
 * against a Ghidra version where those calls resolve to Ghidra's own members, `import ghidrakt.*` looks unused there,
 * and an IDE optimising imports drops it, breaking the build on the versions that need the shim. Using this
 * annotation keeps the import in use on every version.
 */
@Target(AnnotationTarget.FILE)
@Retention(AnnotationRetention.SOURCE)
annotation class UsesShims
