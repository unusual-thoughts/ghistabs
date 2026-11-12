pluginManagement {
    repositories {
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
        // The convention plugins' own plugins, ktlint's among them, are only on the portal.
        gradlePluginPortal()
    }
    // Same catalog as the main build, so versions stay declared in exactly one file.
    versionCatalogs {
        create("libs") { from(files("../gradle/libs.versions.toml")) }
    }
}
