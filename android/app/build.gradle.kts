plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.sentinel.soc"
    compileSdk = 35

    defaultConfig {
        // Placeholder package from the Stage 1 spec. Rename here if the project uses another applicationId.
        applicationId = "com.sentinel.soc"
        minSdk = 26
        targetSdk = 35
        versionCode = 7
        versionName = "0.1.6"
        buildConfigField("String", "CONTRACT_VERSION", "\"1.0\"")
        buildConfigField("int", "MAX_APK_MB", "100")
        // Demo builds reach the laptop over USB (adb reverse) or the hotspot LAN, both plain HTTP.
        buildConfigField("String", "DEFAULT_SERVER_URL", "\"http://127.0.0.1:9000\"")
    }

    buildFeatures {
        buildConfig = true
        viewBinding = true
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
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
    implementation("androidx.recyclerview:recyclerview:1.3.2")
    implementation("androidx.swiperefreshlayout:swiperefreshlayout:1.1.0")
    implementation("androidx.core:core-splashscreen:1.0.1")
    implementation("androidx.work:work-runtime-ktx:2.9.1")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    testImplementation("junit:junit:4.13.2")
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}
