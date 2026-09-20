package com.example.detectorapp

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.bluetooth.*
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.content.Context
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.os.Build
import android.os.Bundle
import android.text.SpannableStringBuilder
import android.text.style.ForegroundColorSpan
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.google.android.material.button.MaterialButton
import java.util.UUID

data class NetworkRow(val bssid: String, val channel: Int, val rssi: Int, val ssid: String, val risk: Boolean)

class MainActivity : AppCompatActivity() {

    private val serviceUuid: UUID = UUID.fromString("12345678-1234-1234-1234-1234567890ab")
    private val authCharUuid: UUID = UUID.fromString("12345678-1234-1234-1234-1234567890ac")
    private val alertCharUuid: UUID = UUID.fromString("12345678-1234-1234-1234-1234567890ad")
    private val cccdUuid: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    private val deviceName = "KARMA-Detector"
    private val password = "changeme123"
    private val channelId = "rogue_ap_alerts"

    private lateinit var statusText: TextView
    private lateinit var statusDot: View
    private lateinit var logText: TextView
    private lateinit var bluetoothAdapter: BluetoothAdapter
    private var bluetoothGatt: BluetoothGatt? = null
    private var alertCharacteristic: BluetoothGattCharacteristic? = null

    private val currentCycleRows = mutableListOf<NetworkRow>()
    private var previousSuspiciousCount = 0

    private val requiredPermissions: Array<String>
        get() = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            arrayOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.POST_NOTIFICATIONS
            )
        } else {
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.statusText)
        statusDot = findViewById(R.id.statusDot)
        logText = findViewById(R.id.logText)

        createNotificationChannel()

        val bluetoothManager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = bluetoothManager.adapter

        findViewById<MaterialButton>(R.id.connectButton).setOnClickListener {
            requestPermissionsThenScan()
        }
    }

    private fun setDotColor(colorRes: Int) {
        statusDot.backgroundTintList = ColorStateList.valueOf(ContextCompat.getColor(this, colorRes))
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId, "Rogue AP Alerts", NotificationManager.IMPORTANCE_HIGH
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun requestPermissionsThenScan() {
        val missing = requiredPermissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, missing.toTypedArray(), 1)
        } else {
            startScan()
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int, permissions: Array<out String>, grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
            startScan()
        } else {
            statusText.text = "Permissions denied — can't scan."
        }
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            if (result.device.name == deviceName) {
                bluetoothAdapter.bluetoothLeScanner.stopScan(this)
                runOnUiThread { statusText.text = "Found device, connecting..." }
                bluetoothGatt = result.device.connectGatt(this@MainActivity, false, gattCallback)
            }
        }
    }

    private fun startScan() {
        statusText.text = "Scanning..."
        logText.text = ""
        setDotColor(R.color.text_muted)
        bluetoothAdapter.bluetoothLeScanner.startScan(scanCallback)
    }

    private val gattCallback = object : BluetoothGattCallback() {

        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                runOnUiThread { statusText.text = "Negotiating packet size..." }
                gatt.requestMtu(247)
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                runOnUiThread {
                    statusText.text = "Disconnected"
                    setDotColor(R.color.text_muted)
                }
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            runOnUiThread { statusText.text = "Discovering services..." }
            gatt.discoverServices()
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            val service = gatt.getService(serviceUuid)
            if (service == null) {
                runOnUiThread { statusText.text = "Service not found on device" }
                return
            }

            alertCharacteristic = service.getCharacteristic(alertCharUuid)
            val authChar = service.getCharacteristic(authCharUuid)

            authChar.value = password.toByteArray(Charsets.UTF_8)
            gatt.writeCharacteristic(authChar)

            runOnUiThread { statusText.text = "Sending password..." }
        }

        override fun onCharacteristicWrite(
            gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int
        ) {
            if (characteristic.uuid == authCharUuid) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    runOnUiThread { statusText.text = "Password write failed" }
                    return
                }

                val alertChar = alertCharacteristic ?: return
                gatt.setCharacteristicNotification(alertChar, true)

                val descriptor = alertChar.getDescriptor(cccdUuid)
                descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                gatt.writeDescriptor(descriptor)

                runOnUiThread { statusText.text = "Enabling alerts..." }
            }
        }

        override fun onDescriptorWrite(
            gatt: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int
        ) {
            runOnUiThread {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    statusText.text = "Connected & listening"
                    setDotColor(R.color.safe)
                } else {
                    statusText.text = "Failed to enable notifications"
                }
            }
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic
        ) {
            val message = String(characteristic.value, Charsets.UTF_8)
            runOnUiThread { handleMessage(message) }
        }
    }

    private fun handleMessage(message: String) {
        when {
            message == "CLR" -> {
                currentCycleRows.clear()
            }
            message.startsWith("ROW|") -> {
                val parts = message.split("|")
                if (parts.size >= 6) {
                    currentCycleRows.add(
                        NetworkRow(
                            bssid = parts[1],
                            channel = parts[2].toIntOrNull() ?: 0,
                            rssi = parts[3].toIntOrNull() ?: 0,
                            ssid = parts[4],
                            risk = parts[5] == "1"
                        )
                    )
                }
            }
            message.startsWith("SUM|") -> {
                val parts = message.split("|")
                val bssidCount = parts.getOrNull(1)?.toIntOrNull() ?: 0
                val ssidCount = parts.getOrNull(2)?.toIntOrNull() ?: 0
                val suspiciousCount = parts.getOrNull(3)?.toIntOrNull() ?: 0

                logText.text = buildTableSpannable(currentCycleRows, bssidCount, ssidCount, suspiciousCount)

                setDotColor(if (suspiciousCount > 0) R.color.alert else R.color.safe)

                if (suspiciousCount > previousSuspiciousCount) {
                    val newlyFlagged = currentCycleRows.filter { it.risk }
                        .map { it.bssid }.distinct().joinToString(", ")
                    showNotification("Rogue BSSID detected: $newlyFlagged")
                }
                previousSuspiciousCount = suspiciousCount
            }
        }
    }

    private fun buildTableSpannable(
        rows: List<NetworkRow>, bssidCount: Int, ssidCount: Int, suspiciousCount: Int
    ): SpannableStringBuilder {
        val sb = SpannableStringBuilder()
        val mutedColor = ContextCompat.getColor(this, R.color.text_muted)
        val normalColor = ContextCompat.getColor(this, R.color.text_primary)
        val riskColor = ContextCompat.getColor(this, R.color.alert)

        fun appendColored(text: String, color: Int) {
            val start = sb.length
            sb.append(text)
            sb.setSpan(ForegroundColorSpan(color), start, sb.length, 0)
        }

        appendColored("============================================================\n", mutedColor)
        appendColored("                    WIFI NETWORKS\n", normalColor)
        appendColored("============================================================\n", mutedColor)
        appendColored(String.format("%-18s %-4s %-6s %s\n", "BSSID", "CH", "RSSI", "SSID"), mutedColor)
        appendColored("------------------------------------------------------------\n", mutedColor)

        for (row in rows) {
            val flag = if (row.risk) "  [!]" else ""
            val line = String.format(
                "%-18s %-4d %-6d %-28s%s\n",
                row.bssid, row.channel, row.rssi, row.ssid, flag
            )
            appendColored(line, if (row.risk) riskColor else normalColor)
        }

        appendColored("------------------------------------------------------------\n", mutedColor)
        appendColored(
            "BSSIDs: $bssidCount | SSIDs: $ssidCount | Suspicious BSSIDs: $suspiciousCount\n",
            if (suspiciousCount > 0) riskColor else mutedColor
        )
        appendColored("============================================================", mutedColor)

        return sb
    }

    private fun showNotification(message: String) {
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED) return

        val notification = NotificationCompat.Builder(this, channelId)
            .setContentTitle("Rogue access point detected")
            .setContentText(message)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setAutoCancel(true)
            .build()

        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(System.currentTimeMillis().toInt(), notification)
    }
}
