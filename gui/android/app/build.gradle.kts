// SPDX-License-Identifier: Apache-2.0
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Signing details live outside the repository, always.
//
// On Android the signing key IS the app's identity: change it and the result
// is a different app that cannot update over the old one. It matters more than
// usual here, because ANDROID_ID is scoped per signing key and key attestation
// binds to the app — so losing this key does not just break updates, it
// re-pairs every handset.
//
// Absent, the release build still runs and produces an UNSIGNED apk, so a CI
// job can check that it compiles without holding the key.
val keystoreProperties = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

android {
    namespace = "org.sysentinel.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "org.sysentinel.app"
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
        minSdk = 21
    }

    // Two products from one source tree, because they are not the same product.
    //
    // `modern` targets a 64-bit handset new enough to have the things this
    // design rests on: StrongBox and BiometricPrompt are both API 28.
    // `legacy` targets a 32-bit handset with a deliberately plain UI; it still
    // runs, it simply cannot prove as much, and the confirmation ladder in
    // daemon/src/confirm.rs already grades it for what it can.
    signingConfigs {
        create("release") {
            val store = keystoreProperties.getProperty("storeFile")
            if (store != null) {
                storeFile = rootProject.file(store)
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            // R8: shrink and obfuscate. Less to reverse, and a smaller APK on
            // the flavour that has to fit an older handset.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            signingConfig = if (keystoreProperties.getProperty("storeFile") != null) {
                signingConfigs.getByName("release")
            } else {
                // Unsigned: it builds, and `apksigner verify` will say so.
                null
            }
        }
        debug {
            isMinifyEnabled = false
        }
    }

    flavorDimensions += "era"
    productFlavors {
        create("modern") {
            dimension = "era"
            minSdk = 28
            ndk { abiFilters += listOf("arm64-v8a") }
            versionNameSuffix = "-modern"
        }
        create("legacy") {
            dimension = "era"
            minSdk = 21
            ndk { abiFilters += listOf("armeabi-v7a") }
            versionNameSuffix = "-legacy"
        }
    }

    buildFeatures {
        compose = true
        viewBinding = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.recyclerview:recyclerview:1.3.2")
    implementation("com.google.android.material:material:1.12.0")

    // The Compose compiler plugin applies to the whole project, so its runtime
    // has to be on every variant's classpath even where no @Composable is
    // written — the legacy flavour carries the runtime and uses none of it.
    // Only the heavy UI libraries are scoped to `modern`, which is where the
    // size actually lives.
    val composeBom = platform("androidx.compose:compose-bom:2024.09.03")
    implementation(composeBom)
    implementation("androidx.compose.runtime:runtime")
    "modernImplementation"("androidx.compose.material3:material3")
    "modernImplementation"("androidx.compose.ui:ui-tooling-preview")
    "modernImplementation"("androidx.activity:activity-compose:1.9.2")
}
