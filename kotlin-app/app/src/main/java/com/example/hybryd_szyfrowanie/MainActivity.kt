package com.example.hybryd_szyfrowanie

import android.annotation.SuppressLint
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PublicKey
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import java.security.PrivateKey

class MainActivity : AppCompatActivity() {

    private lateinit var btnGenerateKey: Button
    private lateinit var btnGetSecret: Button
    private lateinit var btnGetMessage: Button
    private lateinit var tvStatus: TextView
    private lateinit var tvEncryptedMessage: TextView
    private lateinit var tvDecryptedMessage: TextView

    private val keyStore = KeyStore.getInstance("AndroidKeyStore")
    private val keyAlias = "my_rsa_key"
    private val transformation = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initViews()
        setupClickListeners()
        keyStore.load(null)
    }

    private fun initViews() {
        btnGenerateKey = findViewById(R.id.btnGenerateKey)
        btnGetSecret = findViewById(R.id.btnGetSecret)
        btnGetMessage = findViewById(R.id.btnGetMessage)
        tvStatus = findViewById(R.id.tvStatus)
        tvEncryptedMessage = findViewById(R.id.tvEncryptedMessage)
        tvDecryptedMessage = findViewById(R.id.tvDecryptedMessage)
    }

    @SuppressLint("SetTextI18n")
    private fun setupClickListeners() {
        btnGenerateKey.setOnClickListener {
            generateAndSendPublicKey()
        }

        btnGetSecret.setOnClickListener {
  
        }

        btnGetMessage.setOnClickListener {

        }
    }

    @SuppressLint("SetTextI18n")
    private fun generateAndSendPublicKey() {
        tvStatus.text = "Generowanie pary kluczy RSA..."

        try {
            if (!keyStore.containsAlias(keyAlias)) {
                generateRSAKeyPair()
            }

            val entry = keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry
            val publicKey = entry.certificate.publicKey

            val publicKeyBytes = publicKey.encoded 
            val publicKeyBase64 = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)

            tvStatus.text = "Wysyłanie klucza publicznego..."

            ApiService.registerPublicKey(publicKeyBase64) { success, message ->
                runOnUiThread {
                    if (success) {
                        tvStatus.text = message
                        saveKeySentStatus()
                    } else {
                        tvStatus.text = "Błąd: $message"
                    }
                }
            }

        } catch (e: Exception) {
            runOnUiThread {
                tvStatus.text = "Błąd: ${e.message}"
            }
        }
    }

    private fun generateRSAKeyPair() {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                "RSA",
                "AndroidKeyStore"
            )

            val parameterSpec = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or
                        KeyProperties.PURPOSE_DECRYPT
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setKeySize(2048)
                .build()

            keyPairGenerator.initialize(parameterSpec)
            keyPairGenerator.generateKeyPair()

        } catch (e: Exception) {
            throw RuntimeException("Błąd generowania klucza RSA: ${e.message}", e)
        }
    }

    private fun saveKeySentStatus() {
        try {
            val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

            val sharedPreferences = EncryptedSharedPreferences.create(
                "secure_prefs",
                masterKeyAlias,
                this,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )

            with(sharedPreferences.edit()) {
                putBoolean("key_sent", true)
                apply()
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

  
    fun getPrivateKey(): PrivateKey? {
        return try {
            val entry = keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry
            entry.privateKey
        } catch (e: Exception) {
            null
        }
    }

    fun getPublicKey(): PublicKey? {
        return try {
            val entry = keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry
            entry.certificate.publicKey
        } catch (e: Exception) {
            null
        }
    }
}
