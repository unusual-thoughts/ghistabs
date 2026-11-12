// The kernel: Ghidra and Kotlin extensions and the diagnostics both extensions build on. A library, not
// an extension: each extension ships it in its own lib/.
plugins {
    id("ghidra-library")
}

dependencies {
    // GPropertiesFormat is a serialization format, so its users see `-core` too.
    api(libs.kotlinx.serialization.core)
}
