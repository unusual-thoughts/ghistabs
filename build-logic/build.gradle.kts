plugins {
    `kotlin-dsl`
    alias(libs.plugins.ktlint)
}

// ktlint reads the repo-root .editorconfig for these files too. The root build's ktlintCheck /
// ktlintFormat / test fan out to this build; `-p build-logic <task>` runs it standalone.
// `kotlin-dsl` puts its generated accessors/plugin adapters in the main source set; they are not ours to style.
tasks.withType<org.jlleitschuh.gradle.ktlint.tasks.BaseKtLintCheckTask>().configureEach {
    val generated = layout.buildDirectory.dir("generated-sources").get().asFile.toPath()
    exclude { it.file.toPath().startsWith(generated) }
}

dependencies {
    testImplementation(libs.bundles.junit)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test { useJUnitPlatform() }
