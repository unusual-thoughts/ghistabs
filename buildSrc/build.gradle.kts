plugins {
    `kotlin-dsl`
    alias(libs.plugins.ktlint)
}

// Not covered by the root build's ktlintCheck — buildSrc is a separate build.
// Run `./gradlew -p buildSrc ktlintFormat` when touching these files.
ktlint {
    additionalEditorconfig.set(mapOf("ktlint_standard_no-wildcard-imports" to "disabled"))
}

dependencies {
    testImplementation(libs.bundles.junit)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test { useJUnitPlatform() }
