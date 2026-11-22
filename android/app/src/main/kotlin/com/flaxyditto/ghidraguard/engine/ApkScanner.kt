package com.flaxyditto.ghidraguard.engine

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipFile
import kotlin.math.ln

data class ElfSectionInfo(
    val name: String,
    val fileOffset: Long,
    val size: Long,
    val virtualAddress: Long,
    val isExecutable: Boolean,
)

data class NativeLibInfo(
    val entryPath: String,
    val arch: String,
    val entropy: Double,
    val sizeBytes: Long,
    val executableSections: List<ElfSectionInfo> = emptyList(),
    val suspiciousStrings: List<String> = emptyList(),
)

data class ApkThreatFinding(
    val id: String,
    val appName: String,
    val packageName: String,
    val apkPath: String,
    val source: String, // "Installed App", "System App", "Manual APK"
    val riskScore: Int,
    val severity: String, // CRITICAL, HIGH, MEDIUM, LOW
    val maxEntropy: Double,
    val isDebuggable: Boolean,
    val dangerousPermissions: List<String>,
    val indicators: List<String>,
    val suspiciousStrings: List<String>,
    val nativeLibs: List<NativeLibInfo>,
    val dexCount: Int,
    val sha256: String,
)

object ApkScanner {

    private val DANGEROUS_PERMISSIONS = mapOf(
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to 25,
        "android.permission.REQUEST_INSTALL_PACKAGES" to 18,
        "android.permission.SYSTEM_ALERT_WINDOW" to 14,
        "android.permission.RECEIVE_SMS" to 16,
        "android.permission.READ_SMS" to 16,
        "android.permission.SEND_SMS" to 18,
        "android.permission.READ_CONTACTS" to 10,
        "android.permission.RECORD_AUDIO" to 12,
        "android.permission.CAMERA" to 8,
        "android.permission.ACCESS_FINE_LOCATION" to 8,
        "android.permission.READ_CALL_LOG" to 14,
        "android.permission.BIND_DEVICE_ADMIN" to 22,
        "android.permission.RECEIVE_BOOT_COMPLETED" to 6,
        "android.permission.QUERY_ALL_PACKAGES" to 8,
        "android.permission.MANAGE_EXTERNAL_STORAGE" to 12,
    )

    private val SUSPICIOUS_PATTERNS = listOf(
        "DexClassLoader",
        "InMemoryDexClassLoader",
        "Runtime.getRuntime",
        "ProcessBuilder",
        "/system/bin/su",
        "/system/xbin/su",
        "SmsManager",
        "sendTextMessage",
        "AccessibilityService",
        "performGlobalAction",
        "MediaProjection",
        "getDeviceId",
        "getSubscriberId",
        "javax/crypto/Cipher",
        "frida-server",
        "XposedBridge",
        "setComponentEnabledSetting",
        "deletePackage",
        "http://",
        "onion",
        "keylog",
        "beacon",
        "c2_url",
        "exfiltrat",
        "ransom",
    )

    private val IP_REGEX = Regex("""\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b""")
    private val URL_REGEX = Regex("""https?://[a-zA-Z0-9._:/?&=%-]{6,120}""")

    fun shannonEntropy(data: ByteArray, limit: Int = 131072): Double {
        if (data.isEmpty()) return 0.0
        val len = minOf(data.size, limit)
        val counts = IntArray(256)
        for (i in 0 until len) {
            counts[data[i].toInt() and 0xFF]++
        }
        var entropy = 0.0
        val dLen = len.toDouble()
        for (c in counts) {
            if (c > 0) {
                val p = c / dLen
                entropy -= p * (ln(p) / ln(2.0))
            }
        }
        return (entropy * 100.0).toInt() / 100.0
    }

    fun sha256(file: File): String {
        return try {
            val md = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { inp ->
                val buf = ByteArray(16384)
                while (true) {
                    val n = inp.read(buf)
                    if (n <= 0) break
                    md.update(buf, 0, n)
                }
            }
            md.digest().joinToString("") { "%02x".format(it) }
        } catch (_: Exception) {
            "unavailable"
        }
    }

    fun extractAsciiStrings(data: ByteArray, minLen: Int = 5, maxStrings: Int = 400): List<String> {
        val out = ArrayList<String>()
        val sb = StringBuilder()
        val limit = minOf(data.size, 512 * 1024)
        for (i in 0 until limit) {
            val b = data[i].toInt() and 0xFF
            if (b in 32..126) {
                sb.append(b.toChar())
            } else {
                if (sb.length >= minLen) {
                    val s = sb.toString()
                    if (isInterestingString(s)) {
                        out.add(s.take(140))
                        if (out.size >= maxStrings) break
                    }
                }
                sb.setLength(0)
            }
        }
        return out.distinct()
    }

    private fun isInterestingString(s: String): Boolean {
        val low = s.lowercase()
        if (SUSPICIOUS_PATTERNS.any { low.contains(it.lowercase()) }) return true
        if (URL_REGEX.containsMatchIn(s)) return true
        if (IP_REGEX.containsMatchIn(s) && !s.startsWith("127.0.0.") && !s.startsWith("0.0.0.")) return true
        return false
    }

    fun scanInstalledApps(
        context: Context,
        includeSystemApps: Boolean = false,
        minScore: Int = 15,
        onProgress: (Float, String) -> Unit = { _, _ -> },
    ): List<ApkThreatFinding> {
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        val filtered = packages.filter { pkg ->
            val ai = pkg.applicationInfo ?: return@filter false
            val isSys = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            includeSystemApps || !isSys
        }

        val findings = mutableListOf<ApkThreatFinding>()
        val total = maxOf(1, filtered.size)

        filtered.forEachIndexed { idx, pkg ->
            val ai = pkg.applicationInfo ?: return@forEachIndexed
            val appName = try {
                pm.getApplicationLabel(ai).toString()
            } catch (_: Exception) {
                pkg.packageName
            }
            onProgress((idx + 1).toFloat() / total.toFloat(), "Scanning $appName (${idx + 1}/$total)...")

            val isSys = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            val isDebuggable = (ai.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
            val requestedPerms = pkg.requestedPermissions?.toList().orEmpty()
            val apkPath = ai.sourceDir ?: return@forEachIndexed

            val finding = analyzeApkFile(
                apkFile = File(apkPath),
                appName = appName,
                packageName = pkg.packageName,
                source = if (isSys) "System App" else "Installed App",
                requestedPermissions = requestedPerms,
                isDebuggable = isDebuggable,
            )
            if (finding != null && finding.riskScore >= minScore) {
                findings.add(finding)
            }
        }

        return findings.sortedByDescending { it.riskScore }
    }

    fun analyzeApkFile(
        apkFile: File,
        appName: String = apkFile.nameWithoutExtension,
        packageName: String = apkFile.name,
        source: String = "Manual APK",
        requestedPermissions: List<String> = emptyList(),
        isDebuggable: Boolean = false,
    ): ApkThreatFinding? {
        if (!apkFile.isFile || !apkFile.canRead()) return null

        var score = 0
        val indicators = mutableListOf<String>()
        val suspiciousStrings = mutableSetOf<String>()
        val nativeLibs = mutableListOf<NativeLibInfo>()
        var maxEntropy = 0.0
        var dexCount = 0

        // 1. Permission heuristics
        val matchedPerms = requestedPermissions.filter { DANGEROUS_PERMISSIONS.containsKey(it) }
        for (p in matchedPerms) {
            score += DANGEROUS_PERMISSIONS[p] ?: 0
        }
        if (matchedPerms.isNotEmpty()) {
            indicators.add("Dangerous permissions (${matchedPerms.size}): ${matchedPerms.take(4).joinToString { it.substringAfterLast('.') }}")
        }

        // High-risk spyware/dropper combos
        val permSet = requestedPermissions.toSet()
        if (permSet.contains("android.permission.BIND_ACCESSIBILITY_SERVICE") &&
            permSet.contains("android.permission.INTERNET")
        ) {
            score += 20
            indicators.add("High-risk combo: AccessibilityService + INTERNET")
        }
        if (permSet.contains("android.permission.RECEIVE_SMS") &&
            permSet.contains("android.permission.INTERNET")
        ) {
            score += 15
            indicators.add("High-risk combo: SMS interception + INTERNET")
        }

        if (isDebuggable) {
            score += 12
            indicators.add("FLAG_DEBUGGABLE enabled in release package")
        }

        // 2. Inspect APK ZIP entries (DEX + Native ELF .so)
        try {
            ZipFile(apkFile).use { zip ->
                val entries = zip.entries()
                var dexInspected = 0
                var soInspected = 0
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    val name = entry.name

                    if (name.endsWith(".dex")) {
                        dexCount++
                        if (dexInspected < 3) {
                            dexInspected++
                            val bytes = readBounded(zip.getInputStream(entry), 512 * 1024)
                            val ent = shannonEntropy(bytes)
                            if (ent > maxEntropy) maxEntropy = ent
                            val found = extractAsciiStrings(bytes, minLen = 6, maxStrings = 60)
                            suspiciousStrings.addAll(found)
                        }
                    } else if (name.startsWith("lib/") && name.endsWith(".so")) {
                        if (soInspected < 8) {
                            soInspected++
                            val bytes = readBounded(zip.getInputStream(entry), 512 * 1024)
                            val ent = shannonEntropy(bytes)
                            if (ent > maxEntropy) maxEntropy = ent
                            val arch = name.split("/").getOrNull(1) ?: "unknown"
                            val elfSecs = ElfPatcher.parseExecutableSections(bytes)
                            val libStrings = extractAsciiStrings(bytes, minLen = 6, maxStrings = 30)
                            suspiciousStrings.addAll(libStrings)
                            nativeLibs.add(
                                NativeLibInfo(
                                    entryPath = name,
                                    arch = arch,
                                    entropy = ent,
                                    sizeBytes = entry.size,
                                    executableSections = elfSecs,
                                    suspiciousStrings = libStrings,
                                )
                            )
                        }
                    }
                }
            }
        } catch (e: Exception) {
            indicators.add("APK ZIP inspection warning: ${e.message}")
        }

        if (maxEntropy >= 7.2) {
            score += 18
            indicators.add("High entropy ($maxEntropy) suggests packed/encrypted DEX or native payload")
        } else if (maxEntropy >= 6.8) {
            score += 8
            indicators.add("Elevated entropy ($maxEntropy)")
        }

        val dynamicLoadHits = suspiciousStrings.count {
            it.contains("DexClassLoader", ignoreCase = true) ||
                it.contains("Runtime.getRuntime", ignoreCase = true) ||
                it.contains("/su", ignoreCase = true)
        }
        if (dynamicLoadHits > 0) {
            score += minOf(20, dynamicLoadHits * 7)
            indicators.add("Dynamic code execution / shell / root indicators ($dynamicLoadHits)")
        }

        val urlHits = suspiciousStrings.count { it.startsWith("http://", ignoreCase = true) }
        if (urlHits > 0) {
            score += minOf(12, urlHits * 4)
            indicators.add("Cleartext HTTP endpoints found ($urlHits)")
        }

        val clamped = score.coerceIn(0, 100)
        val severity = when {
            clamped >= 70 -> "CRITICAL"
            clamped >= 45 -> "HIGH"
            clamped >= 25 -> "MEDIUM"
            else -> "LOW"
        }

        return ApkThreatFinding(
            id = "${packageName}_${apkFile.lastModified()}",
            appName = appName,
            packageName = packageName,
            apkPath = apkFile.absolutePath,
            source = source,
            riskScore = clamped,
            severity = severity,
            maxEntropy = maxEntropy,
            isDebuggable = isDebuggable,
            dangerousPermissions = matchedPerms,
            indicators = indicators,
            suspiciousStrings = suspiciousStrings.take(50),
            nativeLibs = nativeLibs,
            dexCount = dexCount,
            sha256 = sha256(apkFile),
        )
    }

    private fun readBounded(stream: InputStream, maxBytes: Int): ByteArray {
        stream.use { inp ->
            val buf = ByteArray(maxBytes)
            var total = 0
            while (total < maxBytes) {
                val n = inp.read(buf, total, maxBytes - total)
                if (n <= 0) break
                total += n
            }
            return if (total == maxBytes) buf else buf.copyOf(total)
        }
    }
}
