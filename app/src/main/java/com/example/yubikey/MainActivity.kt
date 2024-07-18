package com.example.yubikey

import android.os.Bundle
import android.widget.ProgressBar
import android.widget.TextView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice
import com.yubico.yubikit.core.*
import com.yubico.yubikit.core.smartcard.SmartCardConnection


class MainActivity : AppCompatActivity() {

    private lateinit var yubikit: YubiKitManager
    private val nfcConfiguration = NfcConfiguration().timeout(60000)

    private lateinit var statusTextView: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var yubikey: NfcYubiKeyDevice

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        statusTextView = findViewById(R.id.tv_status)
        progressBar = findViewById(R.id.progress_bar)

        yubikit = YubiKitManager(this)
        // After asking for Yubikey start with checking for incoming NFC connection
        try {
            yubikit.startNfcDiscovery(nfcConfiguration, this) { device ->
                println("YUBIKEY FOUND")
                runOnUiThread {
                    statusTextView.text = "YubiKey Found!"
                    progressBar.visibility = ProgressBar.GONE
                    yubikey = device
                }
            }
        } catch (e: NfcNotAvailable) {
            println("NO NFC AVAILABLE")
            runOnUiThread {
                statusTextView.text = "NFC Not Available"
                progressBar.visibility = ProgressBar.GONE
            }
        }
    }

    override fun onResume() {
        super.onResume()
    }
}