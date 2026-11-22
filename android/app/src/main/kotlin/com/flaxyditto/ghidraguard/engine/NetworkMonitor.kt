package com.flaxyditto.ghidraguard.engine

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import java.io.File

data class NetworkStatusSummary(
    val transport: String,
    val isVpnActive: Boolean,
    val isValidated: Boolean,
    val localAddresses: List<String>,
    val dnsServers: List<String>,
)

data class SocketConnectionInfo(
    val protocol: String,
    val localAddr: String,
    val remoteAddr: String,
    val state: String,
    val uid: Int,
    val isExternal: Boolean,
)

data class DeviceSecurityCheck(
    val title: String,
    val status: String,
    val isSafe: Boolean,
    val detail: String,
)

object NetworkMonitor {

    fun getNetworkSummary(context: Context): NetworkStatusSummary {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val active = cm.activeNetwork
        val caps = if (active != null) cm.getNetworkCapabilities(active) else null
        val link = if (active != null) cm.getLinkProperties(active) else null

        val transport = when {
            caps == null -> "Offline"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
            else -> "Connected"
        }

        val vpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        val validated = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        val addrs = link?.linkAddresses?.mapNotNull { it.address.hostAddress } ?: emptyList()
        val dns = link?.dnsServers?.mapNotNull { it.hostAddress } ?: emptyList()

        return NetworkStatusSummary(
            transport = transport,
            isVpnActive = vpn,
            isValidated = validated,
            localAddresses = addrs,
            dnsServers = dns,
        )
    }

    fun readActiveSockets(): List<SocketConnectionInfo> {
        val out = mutableListOf<SocketConnectionInfo>()
        out.addAll(parseProcNet("/proc/net/tcp", "TCP"))
        out.addAll(parseProcNet("/proc/net/udp", "UDP"))
        return out.sortedByDescending { it.isExternal }.take(80)
    }

    private fun parseProcNet(path: String, proto: String): List<SocketConnectionInfo> {
        val f = File(path)
        if (!f.canRead()) return emptyList()
        val list = mutableListOf<SocketConnectionInfo>()
        try {
            f.readLines().drop(1).forEach { line ->
                val cols = line.trim().split(Regex("\\s+"))
                if (cols.size >= 8) {
                    val local = decodeIpv4Hex(cols[1])
                    val remote = decodeIpv4Hex(cols[2])
                    val state = decodeTcpState(cols[3])
                    val uid = cols[7].toIntOrNull() ?: -1
                    val ext = !remote.startsWith("0.0.0.0") &&
                        !remote.startsWith("127.") &&
                        !remote.startsWith("192.168.") &&
                        !remote.startsWith("10.")
                    list.add(SocketConnectionInfo(proto, local, remote, state, uid, ext))
                }
            }
        } catch (_: Exception) {
        }
        return list
    }

    private fun decodeIpv4Hex(hexPair: String): String {
        val parts = hexPair.split(":")
        if (parts.size != 2 || parts[0].length != 8) return hexPair
        val ipHex = parts[0]
        val port = parts[1].toIntOrNull(16) ?: 0
        val b0 = ipHex.substring(6, 8).toInt(16)
        val b1 = ipHex.substring(4, 6).toInt(16)
        val b2 = ipHex.substring(2, 4).toInt(16)
        val b3 = ipHex.substring(0, 2).toInt(16)
        return "$b0.$b1.$b2.$b3:$port"
    }

    private fun decodeTcpState(hex: String): String = when (hex.uppercase()) {
        "01" -> "ESTABLISHED"
        "02" -> "SYN_SENT"
        "03" -> "SYN_RECV"
        "06" -> "TIME_WAIT"
        "0A" -> "LISTEN"
        "07" -> "CLOSE"
        else -> "STATE_$hex"
    }

    fun runDeviceSecurityPosture(context: Context): List<DeviceSecurityCheck> {
        val checks = mutableListOf<DeviceSecurityCheck>()

        val adbEnabled = try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        } catch (_: Exception) {
            false
        }
        checks.add(
            DeviceSecurityCheck(
                title = "USB / ADB Debugging",
                status = if (adbEnabled) "ENABLED" else "DISABLED",
                isSafe = !adbEnabled,
                detail = if (adbEnabled) "ADB debugging is active. Disable when not developing." else "ADB debugging is off.",
            )
        )

        val suPaths = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su")
        val hasSu = suPaths.any { File(it).exists() }
        checks.add(
            DeviceSecurityCheck(
                title = "Root / su Binary Check",
                status = if (hasSu) "DETECTED" else "CLEAN",
                isSafe = !hasSu,
                detail = if (hasSu) "su binary found on device filesystem." else "No standard su binaries detected.",
            )
        )

        val testKeys = Build.TAGS?.contains("test-keys") == true
        checks.add(
            DeviceSecurityCheck(
                title = "OS Build Signature",
                status = if (testKeys) "TEST-KEYS" else "RELEASE-KEYS",
                isSafe = !testKeys,
                detail = "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) • ${Build.MANUFACTURER} ${Build.MODEL}",
            )
        )

        val isEmulator = Build.FINGERPRINT.contains("generic", true) ||
            Build.MODEL.contains("Emulator", true) ||
            Build.MODEL.contains("sdk_gphone", true)
        checks.add(
            DeviceSecurityCheck(
                title = "Runtime Environment",
                status = if (isEmulator) "EMULATOR" else "PHYSICAL DEVICE",
                isSafe = true,
                detail = if (isEmulator) "Running in Android Emulator (host desktop reachable at 10.0.2.2)." else "Physical Android hardware.",
            )
        )

        return checks
    }
}
