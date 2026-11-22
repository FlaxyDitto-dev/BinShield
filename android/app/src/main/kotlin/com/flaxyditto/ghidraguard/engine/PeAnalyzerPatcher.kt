package com.flaxyditto.ghidraguard.engine

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Pure-Kotlin Windows PE (.exe / .dll / .sys / .scr) Static Analyzer & Surgical .text Patcher
 * for GhidraGuard Android.
 *
 * Features:
 *  - Parses DOS/PE32/PE32+ headers, sections, entropy, RWX flags, Authenticode presence,
 *    and suspicious Win32 API / C2 / persistence strings.
 *  - Applies surgical x86/x64 byte patches strictly inside executable PE sections
 *    (RET_ZERO `31 C0 C3`, RET_EARLY `C3`, RET_ONE `B8 01 00 00 00 C3`, NOP_SLED, FLIP_JUMP).
 *  - Strips invalidated Authenticode signatures & recalculates PE OptionalHeader CheckSum.
 */
object PeAnalyzerPatcher {

    private const val IMAGE_SCN_MEM_EXECUTE = 0x20000000
    private const val IMAGE_SCN_MEM_WRITE = 0x80000000.toInt()

    private val SUSPICIOUS_WIN32_APIS = listOf(
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtUnmapViewOfSection",
        "QueueUserAPC",
        "SetThreadContext",
        "SetWindowsHookEx",
        "GetAsyncKeyState",
        "GetClipboardData",
        "URLDownloadToFile",
        "InternetOpen",
        "HttpSendRequest",
        "WinHttpOpen",
        "RegSetValueEx",
        "RegCreateKeyEx",
        "CreateService",
        "ShellExecute",
        "CreateProcess",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "CryptEncrypt",
        "BCryptEncrypt",
        "BitBlt",
        "CurrentVersion\\Run",
        "powershell",
        "cmd.exe",
        "vssadmin",
        "schtasks",
    )

    private val SHORT_JCC_FLIP = mapOf(
        0x70 to 0x71, 0x71 to 0x70,
        0x72 to 0x73, 0x73 to 0x72,
        0x74 to 0x75, 0x75 to 0x74,
        0x76 to 0x77, 0x77 to 0x76,
        0x78 to 0x79, 0x79 to 0x78,
        0x7C to 0x7D, 0x7D to 0x7C,
        0x7E to 0x7F, 0x7F to 0x7E,
    )

    private val NEAR_JCC_FLIP = mapOf(
        0x80 to 0x81, 0x81 to 0x80,
        0x82 to 0x83, 0x83 to 0x82,
        0x84 to 0x85, 0x85 to 0x84,
        0x86 to 0x87, 0x87 to 0x86,
        0x88 to 0x89, 0x89 to 0x88,
        0x8C to 0x8D, 0x8D to 0x8C,
        0x8E to 0x8F, 0x8F to 0x8E,
    )

    fun isPeFile(file: File): Boolean {
        if (!file.isFile || !file.canRead() || file.length() < 64) return false
        return try {
            val hdr = ByteArray(64)
            file.inputStream().use { it.read(hdr) }
            hdr[0] == 'M'.code.toByte() && hdr[1] == 'Z'.code.toByte()
        } catch (_: Exception) {
            false
        }
    }

    fun analyzePeFile(peFile: File, displayName: String = peFile.name): ApkThreatFinding? {
        if (!isPeFile(peFile)) return null
        val bytes = try {
            peFile.readBytes()
        } catch (_: Exception) {
            return null
        }
        if (bytes.size < 128) return null

        val bb = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val peOff = bb.getInt(0x3C)
        if (peOff < 0 || peOff + 24 > bytes.size) return null
        if (bytes[peOff] != 'P'.code.toByte() || bytes[peOff + 1] != 'E'.code.toByte() ||
            bytes[peOff + 2] != 0.toByte() || bytes[peOff + 3] != 0.toByte()
        ) {
            return null
        }

        val machine = bb.getShort(peOff + 4).toInt() and 0xFFFF
        val numSections = bb.getShort(peOff + 6).toInt() and 0xFFFF
        val optSize = bb.getShort(peOff + 20).toInt() and 0xFFFF
        val arch = when (machine) {
            0x8664 -> "x86_64"
            0x014C -> "x86"
            0xAA64 -> "arm64"
            else -> "pe_0x${machine.toString(16)}"
        }

        val optOff = peOff + 24
        if (optOff + 2 > bytes.size) return null
        val optMagic = bb.getShort(optOff).toInt() and 0xFFFF
        val isPe32Plus = optMagic == 0x20B

        val imageBase = if (isPe32Plus && optOff + 32 <= bytes.size) {
            bb.getLong(optOff + 24)
        } else if (optOff + 32 <= bytes.size) {
            bb.getInt(optOff + 28).toLong() and 0xFFFFFFFFL
        } else {
            0x400000L
        }

        // Check Authenticode Security Directory (DataDirectory index 4)
        val dataDirOff = optOff + if (isPe32Plus) 112 else 96
        var hasAuthenticode = false
        if (dataDirOff + (5 * 8) <= bytes.size) {
            val secVa = bb.getInt(dataDirOff + 32)
            val secSz = bb.getInt(dataDirOff + 36)
            hasAuthenticode = secVa != 0 && secSz > 0
        }

        // Parse Section Headers
        val secTableOff = optOff + optSize
        val execSections = mutableListOf<ElfSectionInfo>()
        var maxEntropy = 0.0
        var hasRwx = false
        var score = 0
        val indicators = mutableListOf<String>()

        for (i in 0 until numSections) {
            val sOff = secTableOff + i * 40
            if (sOff + 40 > bytes.size) break
            val nameBytes = bytes.copyOfRange(sOff, sOff + 8)
            val secName = String(nameBytes, Charsets.US_ASCII).trim('\u0000').ifBlank { "sec#$i" }
            val virtualAddr = bb.getInt(sOff + 12).toLong() and 0xFFFFFFFFL
            val rawSize = bb.getInt(sOff + 16).toLong() and 0xFFFFFFFFL
            val rawPtr = bb.getInt(sOff + 20).toLong() and 0xFFFFFFFFL
            val chars = bb.getInt(sOff + 36)

            val isExec = (chars and IMAGE_SCN_MEM_EXECUTE) != 0
            val isWrite = (chars and IMAGE_SCN_MEM_WRITE) != 0
            if (isExec && isWrite) hasRwx = true

            if (rawPtr > 0 && rawSize > 0 && rawPtr < bytes.size) {
                val end = minOf(bytes.size, (rawPtr + rawSize).toInt())
                val slice = bytes.copyOfRange(rawPtr.toInt(), end)
                val ent = ApkScanner.shannonEntropy(slice)
                if (ent > maxEntropy) maxEntropy = ent
            }

            if (isExec && rawSize > 0) {
                execSections.add(
                    ElfSectionInfo(
                        name = secName,
                        fileOffset = rawPtr,
                        size = rawSize,
                        virtualAddress = imageBase + virtualAddr,
                        isExecutable = true,
                    )
                )
            }
        }

        if (!hasAuthenticode) {
            score += 15
            indicators.add("Unsigned Windows PE binary (no Authenticode signature)")
        }
        if (hasRwx) {
            score += 20
            indicators.add("Writable + Executable (RWX) PE section detected (packer / shellcode risk)")
        }
        if (maxEntropy >= 7.2) {
            score += 20
            indicators.add("High PE section entropy ($maxEntropy) suggests packing or encryption")
        } else if (maxEntropy >= 6.8) {
            score += 8
            indicators.add("Elevated PE section entropy ($maxEntropy)")
        }

        // Extract ASCII strings & check suspicious Win32 APIs
        val asciiStrings = ApkScanner.extractAsciiStrings(bytes, minLen = 5, maxStrings = 120)
        val rawTextSample = String(bytes, 0, minOf(bytes.size, 1024 * 1024), Charsets.ISO_8859_1)
        val matchedApis = SUSPICIOUS_WIN32_APIS.filter { api ->
            rawTextSample.contains(api, ignoreCase = true)
        }
        if (matchedApis.isNotEmpty()) {
            score += minOf(45, matchedApis.size * 8)
            indicators.add("Suspicious Win32 APIs/strings (${matchedApis.size}): ${matchedApis.take(5).joinToString(", ")}")
        }

        val clamped = score.coerceIn(0, 100)
        val severity = when {
            clamped >= 70 -> "CRITICAL"
            clamped >= 45 -> "HIGH"
            clamped >= 25 -> "MEDIUM"
            else -> "LOW"
        }

        val peLibInfo = NativeLibInfo(
            entryPath = displayName,
            arch = arch,
            entropy = maxEntropy,
            sizeBytes = bytes.size.toLong(),
            executableSections = execSections,
            suspiciousStrings = (matchedApis + asciiStrings).distinct().take(40),
        )

        return ApkThreatFinding(
            id = "pe_${displayName}_${peFile.lastModified()}",
            appName = displayName,
            packageName = "Windows PE ($arch)",
            apkPath = peFile.absolutePath,
            source = "Windows PE (.exe/.dll)",
            riskScore = clamped,
            severity = severity,
            maxEntropy = maxEntropy,
            isDebuggable = false,
            dangerousPermissions = matchedApis.map { "win32.api.$it" },
            indicators = indicators,
            suspiciousStrings = (matchedApis + asciiStrings).distinct().take(50),
            nativeLibs = listOf(peLibInfo),
            dexCount = 0,
            sha256 = ApkScanner.sha256(peFile),
        )
    }

    /**
     * Apply verified surgical byte patches strictly inside executable PE sections,
     * strip invalidated Authenticode signatures, and recalculate PE OptionalHeader CheckSum.
     */
    fun patchPeBinary(
        inputPe: File,
        outputPe: File,
        instructions: List<AndroidPatchInstruction>,
        passNumber: Int = 1,
    ): List<AndroidPatchRecord> {
        val data = inputPe.readBytes()
        val analysis = analyzePeFile(inputPe, inputPe.name)
        val execSections = analysis?.nativeLibs?.firstOrNull()?.executableSections.orEmpty()
        val arch = analysis?.nativeLibs?.firstOrNull()?.arch ?: "x86_64"
        val records = mutableListOf<AndroidPatchRecord>()

        for (inst in instructions) {
            val off = inst.fileOffset.toInt()
            val patchBytes = computePePatchBytes(data, off, inst.strategy, inst.length) ?: continue
            val inExec = execSections.any { sec ->
                inst.fileOffset >= sec.fileOffset &&
                    inst.fileOffset + patchBytes.size <= sec.fileOffset + sec.size
            }
            if (!inExec || off < 0 || off + patchBytes.size > data.size) continue

            val before = data.copyOfRange(off, off + patchBytes.size)
            if (before.contentEquals(patchBytes)) continue

            patchBytes.copyInto(data, destinationOffset = off)
            records.add(
                AndroidPatchRecord(
                    passNumber = passNumber,
                    targetEntry = inputPe.name,
                    functionName = inst.functionName,
                    arch = arch,
                    fileOffsetHex = "0x${off.toString(16)}",
                    strategy = inst.strategy.uppercase(),
                    beforeHex = before.joinToString(" ") { "%02X".format(it) },
                    afterHex = patchBytes.joinToString(" ") { "%02X".format(it) },
                    reason = inst.reason,
                )
            )
        }

        val finalBytes = if (records.isNotEmpty()) stripSignatureAndFixChecksum(data) else data
        outputPe.parentFile?.mkdirs()
        outputPe.writeBytes(finalBytes)
        return records
    }

    private fun computePePatchBytes(data: ByteArray, offset: Int, strategy: String, length: Int): ByteArray? {
        return when (strategy.uppercase().trim()) {
            "RET_EARLY", "RET" -> byteArrayOf(0xC3.toByte())
            "RET_ONE", "RETURN_ONE" -> byteArrayOf(0xB8.toByte(), 0x01, 0x00, 0x00, 0x00, 0xC3.toByte())
            "NOP_SLED", "NOP" -> ByteArray(length.coerceIn(1, 64)) { 0x90.toByte() }
            "FLIP_JUMP", "FLIP_JCC" -> {
                if (offset < 0 || offset >= data.size) return null
                val b0 = data[offset].toInt() and 0xFF
                if (SHORT_JCC_FLIP.containsKey(b0)) {
                    byteArrayOf(SHORT_JCC_FLIP[b0]!!.toByte())
                } else if (b0 == 0x0F && offset + 1 < data.size) {
                    val b1 = data[offset + 1].toInt() and 0xFF
                    if (NEAR_JCC_FLIP.containsKey(b1)) {
                        byteArrayOf(0x0F, NEAR_JCC_FLIP[b1]!!.toByte())
                    } else null
                } else null
            }
            else -> byteArrayOf(0x31, 0xC0.toByte(), 0xC3.toByte()) // RET_ZERO: xor eax, eax; ret
        }
    }

    private fun stripSignatureAndFixChecksum(input: ByteArray): ByteArray {
        var bytes = input.copyOf()
        val bb = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val peOff = bb.getInt(0x3C)
        if (peOff < 0 || peOff + 128 > bytes.size) return bytes
        val optOff = peOff + 24
        val isPe32Plus = (bb.getShort(optOff).toInt() and 0xFFFF) == 0x20B
        val dataDirOff = optOff + if (isPe32Plus) 112 else 96

        // Strip Authenticode Security Directory (index 4)
        if (dataDirOff + 40 <= bytes.size) {
            val certOff = bb.getInt(dataDirOff + 32)
            val certSize = bb.getInt(dataDirOff + 36)
            if (certOff > 0 && certSize > 0) {
                bb.putInt(dataDirOff + 32, 0)
                bb.putInt(dataDirOff + 36, 0)
                if (certOff + certSize >= bytes.size - 16 && certOff < bytes.size) {
                    bytes = bytes.copyOf(certOff)
                }
            }
        }

        // Recalculate standard Windows PE CheckSum (at optOff + 64)
        val csumOff = optOff + 64
        if (csumOff + 4 <= bytes.size) {
            val bb2 = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            bb2.putInt(csumOff, 0)
            var sum = 0L
            var i = 0
            while (i < bytes.size) {
                val lo = bytes[i].toInt() and 0xFF
                val hi = if (i + 1 < bytes.size) bytes[i + 1].toInt() and 0xFF else 0
                val word = lo or (hi shl 8)
                sum += word
                sum = (sum and 0xFFFFL) + (sum ushr 16)
                i += 2
            }
            sum = (sum and 0xFFFFL) + (sum ushr 16)
            val finalChecksum = (sum + bytes.size.toLong()).toInt()
            bb2.putInt(csumOff, finalChecksum)
        }
        return bytes
    }
}
