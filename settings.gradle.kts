// build-logic is an ordinary included build rather than `buildSrc`, so the root build can address its
// tasks (`gradle.includedBuild("build-logic").task(...)`): `buildSrc` is a reserved build name and is
// unreachable from the root task graph.
pluginManagement {
    includeBuild("build-logic")
}

// Pinned, not derived from the directory name: `${project.name}` names the extension jar and zip.
rootProject.name = "ghistabs"
