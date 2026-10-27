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

    // BouncyCastle: hybrid X25519 + ML-KEM-768 E2E encryption, built to be
    // byte-for-byte wire-compatible with the Rust CLI's crypto/src/e2e.rs
    // (HKDF-SHA256 + XChaCha20-Poly1305 on top of the same two key
    // agreements). This REPLACED Tink's HPKE, which was classical-only and
    // produced an incompatible ciphertext format — an Android user and a
    // CLI user could not read each other's messages under it. Every
    // non-obvious class here (org.bouncycastle.crypto.{generators,kems,
    // modes,params}.MLKEM*/X25519*/HKDF*/XChaCha20Poly1305/AEADParameters)
    // was checked against the real javadoc before being used.
    implementation("org.bouncycastle:bcprov-jdk18on:1.78")

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
