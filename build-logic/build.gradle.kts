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

// The plugins the convention plugins apply, at the catalog's versions: the subprojects then apply them by
// id alone, since a plugin on the build classpath takes no version.
fun plugin(p: Provider<PluginDependency>) = p.map { "${it.pluginId}:${it.pluginId}.gradle.plugin:${it.version}" }

dependencies {
    implementation(plugin(libs.plugins.kotlin.jvm))
    implementation(plugin(libs.plugins.kotlin.serialization))
    implementation(plugin(libs.plugins.ktlint))
    implementation(plugin(libs.plugins.detekt))
    testImplementation(libs.bundles.junit)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test { useJUnitPlatform() }
