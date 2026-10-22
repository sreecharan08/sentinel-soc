// Harmless Stage 7 fixture: declares risky permissions and carries indicator strings it never acts on.
// Variants: debug -> exp_plain.apk (R8 off), r8 -> exp_r8.apk (identifier renaming, the URL kept by a keep rule).
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.demo.expfixture"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.demo.expfixture"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        create("r8") {
            initWith(getByName("debug"))
            isDebuggable = false          // R8 is disabled for debuggable builds
            isMinifyEnabled = true
            isShrinkResources = false
            signingConfig = signingConfigs.getByName("debug")
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
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
