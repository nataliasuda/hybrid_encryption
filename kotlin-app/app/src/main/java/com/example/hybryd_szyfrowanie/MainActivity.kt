package com.example.hybryd_szyfrowanie

import android.annotation.SuppressLint
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import javax.crypto.Cipher

class MainActivity : AppCompatActivity() {

    private lateinit var btnGenerateKey: Button
    private lateinit var btnGetSecret: Button
    private lateinit var btnGetMessage: Button
    private lateinit var tvStatus: TextView
    private lateinit var tvEncryptedMessage: TextView
    private lateinit var tvDecryptedMessage: TextView

    private val keyStore = KeyStore.getInstance("AndroidKeyStore")
    private val keyAlias = "my_rsa_key"

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
            tvStatus.text = "Pobieranie zaszyfrowanego AES..."
            ApiService.getEncryptedSecret { success, encryptedSecret, message ->
                runOnUiThread {
                    if (!success || encryptedSecret == null) {
                        tvStatus.text = "Błąd pobierania: $message"
                        return@runOnUiThread
                    }

                    try {
                        tvEncryptedMessage.text = "Szyfrogram AES (base64):\n$encryptedSecret"
                        val aesKeyBytes = decryptAESKey(encryptedSecret)
                        tvStatus.text = "Sekret AES odszyfrowany! Długość: ${aesKeyBytes.size} B"
                        saveAESKey(aesKeyBytes)
                        tvDecryptedMessage.text = "AES zapisany w EncryptedSharedPreferences"
                    } catch (e: Exception) {
                        tvStatus.text = "Błąd RSA: ${e.message}"
                    }
                }
            }
        }

        btnGetMessage.setOnClickListener {
           
        }
    }

    @SuppressLint("SetTextI18n")
    private fun generateAndSendPublicKey() {
        tvStatus.text = "Generowanie pary kluczy RSA..."
        try {
            if (keyStore.containsAlias(keyAlias)) {
                keyStore.deleteEntry(keyAlias)
            }

            generateRSAKeyPair()

            val entry = keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry
            val publicKey = entry.certificate.publicKey

            val der = publicKey.encoded
            val pemBody = Base64.encodeToString(der, Base64.NO_WRAP)
            val pemString = "-----BEGIN PUBLIC KEY-----\n$pemBody\n-----END PUBLIC KEY-----\n"
            val pemBase64 = Base64.encodeToString(pemString.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)

            tvStatus.text = "Wysyłanie klucza publicznego..."
            ApiService.registerPublicKey(pemBase64) { success, message ->
                runOnUiThread {
                    tvStatus.text = message
                }
            }
        } catch (e: Exception) {
            tvStatus.text = "Błąd: ${e.message ?: e.javaClass.simpleName}"
        }
    }

    private fun generateRSAKeyPair() {
        val generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setDigests(KeyProperties.DIGEST_SHA1) 
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setKeySize(2048)
            .build()

        generator.initialize(spec)
        generator.generateKeyPair()
    }

    private fun decryptAESKey(base64Cipher: String): ByteArray {
        val cipherBytes = Base64.decode(base64Cipher.replace("\\s".toRegex(), ""), Base64.DEFAULT)
        val privateKey = getPrivateKey() ?: throw Exception("Brak klucza prywatnego w KeyStore!")
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return cipher.doFinal(cipherBytes)
    }

    private fun saveAESKey(aesBytes: ByteArray) {
        val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
        val prefs = EncryptedSharedPreferences.create(
            "secure_prefs",
            masterKeyAlias,
            this,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
        prefs.edit().putString("aes_key", Base64.encodeToString(aesBytes, Base64.NO_WRAP)).apply()
    }

    private fun getPrivateKey(): PrivateKey? {
        return try {
            val entry = keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry
            entry.privateKey
        } catch (e: Exception) {
            null
        }
    }
}