plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.veil.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.veil.app"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.1")
    implementation(platform("androidx.compose:compose-bom:2024.06.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")
    implementation("androidx.navigation:navigation-compose:2.7.7")

    // Real, audited crypto — not a hand-rolled scheme. Google's Tink
    // provides standardized HPKE (RFC 9180, X25519-based) for E2E, used the
    // same way the web prototype and CLI use their own public-key schemes:
    // client-side only, server never has a decryption key.
    implementation("com.google.crypto.tink:tink-android:1.14.1")

    // Argon2id for the app lock — the real reference Argon2 implementation
    // via JNI, not a Java re-implementation of the algorithm.
    implementation("com.lambdapioneer.argon2kt:argon2kt:1.6.0")

    // Networking: the same backend the CLI and web prototype talk to.
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.squareup.retrofit2:retrofit:2.11.0")
    implementation("com.squareup.retrofit2:converter-gson:2.11.0")

    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
