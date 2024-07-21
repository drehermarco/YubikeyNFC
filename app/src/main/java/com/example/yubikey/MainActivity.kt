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
import com.yubico.yubikit.core.smartcard.ApduException
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.openpgp.Pw
import com.yubico.yubikit.piv.KeyType
import com.yubico.yubikit.piv.PinPolicy
import com.yubico.yubikit.piv.PivSession
import com.yubico.yubikit.piv.Slot
import com.yubico.yubikit.piv.TouchPolicy
import com.yubico.yubikit.piv.jca.PivProvider
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.nio.charset.StandardCharsets
import java.security.Security
import java.security.Signature
import kotlin.properties.Delegates


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
    private var hasNfc by Delegates.notNull<Boolean>()

    private lateinit var statusTextView: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var yubikey: NfcYubiKeyDevice
    private lateinit var conn: SmartCardConnection
    private lateinit var piv: PivSession

    private lateinit var keypairAuth: PublicKeyValues
    private lateinit var keypairSign: PublicKeyValues

    lateinit var managementKeyTypeTextView: TextView
    private lateinit var managementTouchPolicyTextView: TextView
    private lateinit var pinTotalAttemptsTextView: TextView
    private lateinit var pinAttemptsRemainingTextView: TextView
    private lateinit var pukTotalAttemptsTextView: TextView
    private lateinit var pukAttemptsRemainingTextView: TextView
    private lateinit var authPublicKeyTextView: TextView
    private lateinit var authKeyTypeTextView: TextView
    private lateinit var authTouchPolicyTextView: TextView
    private lateinit var authPinPolicyTextView: TextView
    private lateinit var signPublicKeyTextView: TextView
    private lateinit var signKeyTypeTextView: TextView
    private lateinit var signTouchPolicyTextView: TextView
    private lateinit var signPinPolicyTextView: TextView
    private lateinit var signMessageTextView: TextView

    private lateinit var signedString: String

    val metadataInfo = StringBuilder()

    private fun verify(piv: PivSession) {
        piv.verifyPin(DEFAULT_PIN)
        piv.authenticate(DEFAULT_MGMT)
    }

    private fun checkForKey(piv: PivSession, slot: Slot): Boolean {
        try {
            if (slot == Slot.AUTHENTICATION) {
                piv.getSlotMetadata(Slot.AUTHENTICATION).publicKeyValues.toPublicKey().toString()
            } else if (slot == Slot.SIGNATURE) {
                piv.getSlotMetadata(Slot.SIGNATURE).publicKeyValues.toPublicKey().toString()
            }
        } catch (e: ApduException) {
            return false
        }
        return true
    }

    private fun retrieveKey(piv: PivSession, slot: Slot): PublicKeyValues {
        return piv.getSlotMetadata(slot).publicKeyValues
    }


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.tv_status)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        progressBar = findViewById(R.id.progress_bar)
        statusTextView = findViewById(R.id.tv_status)

        statusTextView.text = "Please connect your Yubikey"

        yubikit = YubiKitManager(this)
        try {
            yubikit.startNfcDiscovery(nfcConfiguration, this) { device ->
                runOnUiThread {
                    yubikey = device
                    hasNfc = true

                    yubikey.requestConnection(SmartCardConnection::class.java) { result ->
                        conn = result.value
                        piv = PivSession(conn)

                        verify(piv)

                        Security.removeProvider("BC")
                        Security.addProvider(BouncyCastleProvider())


                        if (!checkForKey(piv, Slot.AUTHENTICATION)) {
                            piv.generateKeyValues(
                                Slot.AUTHENTICATION, KeyType.ED25519,
                                PinPolicy.DEFAULT, TouchPolicy.DEFAULT
                            )
                        }
                        if (!checkForKey(piv, Slot.SIGNATURE)) {
                            piv.generateKeyValues(
                                Slot.SIGNATURE, KeyType.ED25519,
                                PinPolicy.DEFAULT, TouchPolicy.DEFAULT
                            )
                        }

                        keypairAuth = retrieveKey(piv, Slot.AUTHENTICATION)
                        keypairSign = retrieveKey(piv, Slot.SIGNATURE)

                        val message = "DPIA".toByteArray(StandardCharsets.UTF_8)
                        val signed = piv.sign(
                            Slot.SIGNATURE,
                            KeyType.ED25519,
                            message, Signature.getInstance("SHA3-256withECDSA")
                        )
                        signedString = "Signature of message ''DPIA'': ${signed.joinToString("") { "%02x".format(it) }}"

                        /* This doesn't work because signing algorithm isn't compatible with verify
                        val signature = Signature.getInstance("SHA3-512withECDSA")
                        signature.initVerify(keypairSign.toPublicKey())
                        signature.update(message)
                        val isValid = signature.verify(signed)
                        println("Signature verified: $isValid")
                        */

                        //Append Strings
                        metadataInfo.append("Management Key Metadata:\n")
                        metadataInfo.append("Key Type: ${piv.managementKeyMetadata.keyType}\n")
                        metadataInfo.append("Touch Policy: ${piv.managementKeyMetadata.touchPolicy}\n")
                        metadataInfo.append("\nPIN Metadata:\n")
                        metadataInfo.append("Total Attempts: ${piv.pinMetadata.totalAttempts}\n")
                        metadataInfo.append("Attempts Remaining: ${piv.pinMetadata.attemptsRemaining}\n")
                        metadataInfo.append("\nPUK Metadata:\n")
                        metadataInfo.append("Total Attempts: ${piv.pukMetadata.totalAttempts}\n")
                        metadataInfo.append("Attempts Remaining: ${piv.pukMetadata.attemptsRemaining}\n")
                        metadataInfo.append("\nAuthentication Slot Metadata:\n")
                        metadataInfo.append("Public Key: ${piv.getSlotMetadata(Slot.AUTHENTICATION).publicKeyValues.toPublicKey()}\n")
                        metadataInfo.append("Key Type: ${piv.getSlotMetadata(Slot.AUTHENTICATION).keyType}\n")
                        metadataInfo.append("Touch Policy: ${piv.getSlotMetadata(Slot.AUTHENTICATION).touchPolicy}\n")
                        metadataInfo.append("Pin Policy: ${piv.getSlotMetadata(Slot.AUTHENTICATION).pinPolicy}\n")
                        metadataInfo.append("\nSignature Slot Metadata:\n")
                        metadataInfo.append("Public Key: ${piv.getSlotMetadata(Slot.SIGNATURE).publicKeyValues.toPublicKey()}\n")
                        metadataInfo.append("Key Type: ${piv.getSlotMetadata(Slot.SIGNATURE).keyType}\n")
                        metadataInfo.append("Touch Policy: ${piv.getSlotMetadata(Slot.SIGNATURE).touchPolicy}\n")
                        metadataInfo.append("Pin Policy: ${piv.getSlotMetadata(Slot.SIGNATURE).pinPolicy}\n")
                        metadataInfo.append("\n$signedString")


                        //conn.close()



                    }
                    Thread.sleep(2000)
                    progressBar.visibility = ProgressBar.GONE
                    statusTextView.text = metadataInfo
                }

            }


        } catch (e: Exception) {
            e.printStackTrace()
            println("An error occurred during NFC discovery: ${e.message}")
        }
    }

    override fun onPause() {
        if (hasNfc) {
            yubikit.stopNfcDiscovery(this)
        }
        super.onPause()
    }
}