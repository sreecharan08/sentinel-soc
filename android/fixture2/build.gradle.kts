// Harmless "flag me for sure" test app for the SOC pipeline. It DECLARES many risky permissions and carries indicator
// strings plus references to risky APIs inside functions nothing ever calls, so static analysis scores it malicious.
// It does not request, use or execute any of it at runtime. Never shipped to users.
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.demo.malwaretest"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.demo.malwaretest"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}
