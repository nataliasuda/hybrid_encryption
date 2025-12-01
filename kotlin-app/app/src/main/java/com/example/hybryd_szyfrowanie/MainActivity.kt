package com.example.hybryd_szyfrowanie

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    
    private lateinit var btnGenerateKey: Button
    private lateinit var btnGetSecret: Button
    private lateinit var btnGetMessage: Button
    private lateinit var tvStatus: TextView
    private lateinit var tvEncryptedMessage: TextView
    private lateinit var tvDecryptedMessage: TextView
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        initViews()
        
        setupButtonListeners()
    }
    
    private fun initViews() {
        btnGenerateKey = findViewById(R.id.btnGenerateKey)
        btnGetSecret = findViewById(R.id.btnGetSecret)
        btnGetMessage = findViewById(R.id.btnGetMessage)
        tvStatus = findViewById(R.id.tvStatus)
        tvEncryptedMessage = findViewById(R.id.tvEncryptedMessage)
        tvDecryptedMessage = findViewById(R.id.tvDecryptedMessage)
    }
    
    private fun setupButtonListeners() {
        btnGenerateKey.setOnClickListener {
           
        }
        
 
        btnGetSecret.setOnClickListener {
           
        }
        
       
        btnGetMessage.setOnClickListener {
           
        }
    }
    
    private fun updateStatus(message: String) {
        tvStatus.text = message
    }
    

    fun setEncryptedMessage(message: String) {
        tvEncryptedMessage.text = message
    }
    
    fun setDecryptedMessage(message: String) {
        tvDecryptedMessage.text = message
    }
}