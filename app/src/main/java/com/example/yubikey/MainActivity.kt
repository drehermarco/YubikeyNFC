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
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice
import com.yubico.yubikit.core.keys.PublicKeyValues
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.openpgp.Pw
import com.yubico.yubikit.piv.KeyType
import com.yubico.yubikit.piv.PinPolicy
import com.yubico.yubikit.piv.PivSession
import com.yubico.yubikit.piv.Slot
import com.yubico.yubikit.piv.TouchPolicy
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.security.Key
import java.security.KeyPair
import java.security.Security


class MainActivity : AppCompatActivity() {
    private val DEFAULT_PIN: CharArray = Pw.DEFAULT_USER_PIN
    private val DEFAULT_ADMIN: CharArray = Pw.DEFAULT_ADMIN_PIN
    private val DEFAULT_MGMT = byteArrayOf(
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    )

    private lateinit var yubikit: YubiKitManager
    private val nfcConfiguration = NfcConfiguration().timeout(60000)

    private lateinit var statusTextView: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var yubikey: NfcYubiKeyDevice
    private lateinit var conn: SmartCardConnection
    private lateinit var piv: PivSession

    private lateinit var keypairAuth: PublicKeyValues
    private lateinit var keypairSign: PublicKeyValues

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        Security.removeProvider("BC")
        Security.addProvider(BouncyCastleProvider())

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
        try {
            yubikit.startNfcDiscovery(nfcConfiguration, this) { device ->
                runOnUiThread {
                    statusTextView.text = "Yubikey found!"
                    progressBar.visibility = ProgressBar.GONE
                    yubikey = device
                    yubikey.requestConnection(SmartCardConnection::class.java) { result ->
                        conn = result.value
                        piv = PivSession(conn)
                        piv.verifyPin(DEFAULT_PIN)
                        piv.authenticate(DEFAULT_MGMT)
                        keypairAuth = piv.generateKeyValues(Slot.AUTHENTICATION, KeyType.ED25519,
                                        PinPolicy.DEFAULT, TouchPolicy.DEFAULT)
                        keypairSign = piv.generateKeyValues(Slot.SIGNATURE, KeyType.ED25519,
                                        PinPolicy.DEFAULT, TouchPolicy.DEFAULT)
                        println(keypairAuth)
                        println(keypairSign)
                    }
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
            println("An error occurred during NFC discovery: ${e.message}")
        }
    }
}