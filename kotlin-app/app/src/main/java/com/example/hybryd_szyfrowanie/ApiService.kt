package com.example.hybryd_szyfrowanie

import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.logging.HttpLoggingInterceptor
import org.json.JSONObject
import java.io.IOException

class ApiService {
    companion object {
        private const val BASE_URL = "http://10.0.2.2:8000"

        private val JSON_MEDIA_TYPE = "application/json".toMediaType()
        private val client = OkHttpClient.Builder()
            .addInterceptor(HttpLoggingInterceptor().apply {
                level = HttpLoggingInterceptor.Level.BODY
            })
            .build()

        fun registerPublicKey(
            publicKeyBase64: String,
            callback: (success: Boolean, message: String) -> Unit
        ) {
            Thread {
                try {
                    val json = JSONObject()
                    json.put("public_key", publicKeyBase64)

                    val requestBody = json.toString().toRequestBody(JSON_MEDIA_TYPE)

                    val request = Request.Builder()
                        .url("$BASE_URL/register-key")
                        .post(requestBody)
                        .build()

                    val response = client.newCall(request).execute()

                    if (response.isSuccessful) {
                        val responseBody = response.body?.string()
                        callback(true, "Klucz wysłany, status: ok")
                    } else {
                        callback(false, "Błąd HTTP: ${response.code}")
                    }
                } catch (e: Exception) {
                    callback(false, "Błąd: ${e.message}")
                }
            }.start()
        }
    }
}