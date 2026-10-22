pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "sentinel-android"
include(":app")
include(":fixture2")   // "flag me for sure" harmless malware-test fixture
include(":fixture")   // harmless test fixture (exp_plain / exp_r8); never shipped to users
