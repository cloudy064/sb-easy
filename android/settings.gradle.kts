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
        flatDir { dirs("libbox-bridge/libs") }
    }
}

rootProject.name = "sb-easy-android"
include(":app", ":core", ":libbox-bridge")
