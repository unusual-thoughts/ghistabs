plugins {
    `kotlin-dsl`
    alias(libs.plugins.ktlint)
}

// ktlint reads the repo-root .editorconfig for these files too, but the root build's ktlintCheck
// can't reach a separate build: run `./gradlew -p buildSrc ktlintFormat` when touching them.
dependencies {
    testImplementation(libs.bundles.junit)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test { useJUnitPlatform() }
