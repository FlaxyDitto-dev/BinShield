package com.flaxyditto.ghidraguard.engine

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Pure-Kotlin Streaming Windows PE (.exe / .dll / .sys / .scr) Static Analyzer & Surgical .text Patcher
 * for BinShield Android.
 *
 * Uses RandomAccessFile + 1 MB streaming I/O so there is NO FILE SIZE LIMIT (handles multi-GB
 * game executables with constant O(1) RAM).
 */
object PeAnalyzerPatcher {

    private const val IMAGE_SCN_MEM_EXECUTE = 0x20000000
    private const val IMAGE_SCN_MEM_WRITE = 0x80000000.toInt()
    private const val STREAM_CHUNK = 1024 * 1024

    private val PROXY_SIDELOAD_DLL_NAMES = setOf(
        "version.dll", "dinput8.dll", "dxgi.dll", "d3d11.dll", "d3d12.dll",
        "winmm.dll", "dbghelp.dll", "xinput1_3.dll", "xinput1_4.dll",
        "wsock32.dll", "winhttp.dll", "cryptbase.dll", "msimg32.dll",
        "uxtheme.dll", "bink2w64.dll",
    )

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
        val fileLen = peFile.length()
        if (fileLen < 128L) return null

        val execSections = mutableListOf<ElfSectionInfo>()
        var maxEntropy = 0.0
        var hasRwx = false
        var hasInjectedExecSection = false
        var hasOepHijack = false
        var hasMaliciousOverlay = false
        var hasAuthenticode = false
        var peRawEnd = 0L
        var epRva = 0L
        var textVStart = 0L
        var textVEnd = 0L
        var arch = "unknown"
        val matchedApis = linkedSetOf<String>()
        val asciiStrings = linkedSetOf<String>()
        val standardExecNames = setOf(".text", "text", "code", ".code", "init", "page", ".itext")

        try {
            RandomAccessFile(peFile, "r").use { raf ->
                val dos = ByteArray(64)
                raf.readFully(dos)
                val peOff = ByteBuffer.wrap(dos).order(ByteOrder.LITTLE_ENDIAN).getInt(0x3C).toLong()
                if (peOff < 0 || peOff + 24 > fileLen) return null

                raf.seek(peOff)
                val coff = ByteArray(24)
                raf.readFully(coff)
                if (coff[0] != 'P'.code.toByte() || coff[1] != 'E'.code.toByte() ||
                    coff[2] != 0.toByte() || coff[3] != 0.toByte()
                ) {
                    return null
                }

                val cbb = ByteBuffer.wrap(coff).order(ByteOrder.LITTLE_ENDIAN)
                val machine = cbb.getShort(4).toInt() and 0xFFFF
                val numSections = cbb.getShort(6).toInt() and 0xFFFF
                val optSize = cbb.getShort(20).toInt() and 0xFFFF
                arch = when (machine) {
                    0x8664 -> "x86_64"
                    0x014C -> "x86"
                    0xAA64 -> "arm64"
                    else -> "pe_0x${machine.toString(16)}"
                }

                val optBufSize = minOf(optSize, maxOf(0, (fileLen - (peOff + 24)).toInt()))
                if (optBufSize < 2) return null
                val optBytes = ByteArray(optBufSize)
                raf.seek(peOff + 24)
                raf.readFully(optBytes)
                val obb = ByteBuffer.wrap(optBytes).order(ByteOrder.LITTLE_ENDIAN)
                val optMagic = obb.getShort(0).toInt() and 0xFFFF
                val isPe32Plus = optMagic == 0x20B

                val imageBase = if (isPe32Plus && optBytes.size >= 32) {
                    obb.getLong(24)
                } else if (optBytes.size >= 32) {
                    obb.getInt(28).toLong() and 0xFFFFFFFFL
                } else {
                    0x400000L
                }
                if (optBytes.size >= 20) {
                    epRva = obb.getInt(16).toLong() and 0xFFFFFFFFL
                }

                val dataDirRel = if (isPe32Plus) 112 else 96
                if (dataDirRel + 40 <= optBytes.size) {
                    val secVa = obb.getInt(dataDirRel + 32)
                    val secSz = obb.getInt(dataDirRel + 36)
                    hasAuthenticode = secVa != 0 && secSz > 0
                }

                // Read Section Table (only 40 bytes per section)
                val secTableOff = peOff + 24 + optSize
                val secHeader = ByteArray(40)
                val entropySampleBuf = ByteArray(256 * 1024)
                for (i in 0 until numSections) {
                    val sOff = secTableOff + i.toLong() * 40L
                    if (sOff + 40L > fileLen) break
                    raf.seek(sOff)
                    raf.readFully(secHeader)
                    val sbb = ByteBuffer.wrap(secHeader).order(ByteOrder.LITTLE_ENDIAN)
                    val secName = String(secHeader, 0, 8, Charsets.US_ASCII).trim('\u0000').ifBlank { "sec#$i" }
                    val virtualAddr = sbb.getInt(12).toLong() and 0xFFFFFFFFL
                    val rawSize = sbb.getInt(16).toLong() and 0xFFFFFFFFL
                    val rawPtr = sbb.getInt(20).toLong() and 0xFFFFFFFFL
                    val chars = sbb.getInt(36)

                    val isExec = (chars and IMAGE_SCN_MEM_EXECUTE) != 0
                    val isWrite = (chars and IMAGE_SCN_MEM_WRITE) != 0
                    if (isExec && isWrite) hasRwx = true
                    val secLow = secName.lowercase()
                    if (isExec && secLow !in standardExecNames) hasInjectedExecSection = true
                    if (secLow in standardExecNames && textVEnd == 0L) {
                        textVStart = virtualAddr
                        textVEnd = virtualAddr + maxOf(sbb.getInt(8).toLong() and 0xFFFFFFFFL, rawSize)
                    }
                    if (rawPtr + rawSize > peRawEnd) {
                        peRawEnd = rawPtr + rawSize
                    }

                    if (rawPtr > 0L && rawSize > 0L && rawPtr < fileLen) {
                        val toRead = minOf(entropySampleBuf.size.toLong(), rawSize, fileLen - rawPtr).toInt()
                        if (toRead > 0) {
                            raf.seek(rawPtr)
                            raf.readFully(entropySampleBuf, 0, toRead)
                            val ent = ApkScanner.shannonEntropy(entropySampleBuf, limit = toRead)
                            if (ent > maxEntropy) maxEntropy = ent
                        }
                    }

                    if (isExec && rawSize > 0L) {
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
                if (epRva > 0L && textVEnd > 0L && (epRva < textVStart || epRva >= textVEnd)) {
                    hasOepHijack = true
                }
                if (!hasAuthenticode && peRawEnd > 0L && fileLen - peRawEnd >= 64L) {
                    val ovLen = minOf(4096L, fileLen - peRawEnd).toInt()
                    val ovBuf = ByteArray(ovLen)
                    raf.seek(peRawEnd)
                    raf.readFully(ovBuf)
                    val ovText = String(ovBuf, Charsets.ISO_8859_1).lowercase()
                    if ((ovBuf[0] == 'M'.code.toByte() && ovBuf[1] == 'Z'.code.toByte()) ||
                        ovText.contains("powershell") || ovText.contains("gg_overlay_payload") ||
                        ovText.contains("discord.com/api/webhooks")
                    ) {
                        hasMaliciousOverlay = true
                    }
                }
            }

            // Stream-scan entire file in 1 MB chunks for Win32 API indicators & strings (zero size limit)
            val buf = ByteArray(STREAM_CHUNK)
            FileInputStream(peFile).use { fis ->
                var chunksRead = 0
                while (true) {
                    val n = fis.read(buf)
                    if (n <= 0) break
                    chunksRead++
                    val chunkText = String(buf, 0, n, Charsets.ISO_8859_1)
                    for (api in SUSPICIOUS_WIN32_APIS) {
                        if (api !in matchedApis && chunkText.contains(api, ignoreCase = true)) {
                            matchedApis.add(api)
                        }
                    }
                    if (asciiStrings.size < 60 && chunksRead <= 16) {
                        val slice = if (n == buf.size) buf else buf.copyOf(n)
                        asciiStrings.addAll(ApkScanner.extractAsciiStrings(slice, minLen = 5, maxStrings = 30))
                    }
                }
            }
        } catch (_: Exception) {
            return null
        }

        var score = 0
        val indicators = mutableListOf<String>()
        if (!hasAuthenticode) {
            score += 15
            indicators.add("Unsigned Windows PE binary (no Authenticode signature)")
        }
        if (hasRwx) {
            score += 20
            indicators.add("Writable + Executable (RWX) PE section detected (packer / shellcode risk)")
        }
        if (hasInjectedExecSection) {
            score += 30
            indicators.add("Non-standard executable PE section detected (code injection risk)")
        }
        if (hasOepHijack) {
            score += 35
            indicators.add("EntryPoint (OEP) points outside primary .text section (OEP hijack risk)")
        }
        if (hasMaliciousOverlay) {
            score += 30
            indicators.add("Malicious PE overlay payload detected after last section")
        }
        if (maxEntropy >= 7.2) {
            score += 20
            indicators.add("High PE section entropy ($maxEntropy) suggests packing or encryption")
        } else if (maxEntropy >= 6.8) {
            score += 8
            indicators.add("Elevated PE section entropy ($maxEntropy)")
        }
        if (matchedApis.isNotEmpty()) {
            score += minOf(45, matchedApis.size * 8)
            indicators.add("Suspicious Win32 APIs/strings (${matchedApis.size}): ${matchedApis.take(5).joinToString(", ")}")
        }
        if (displayName.lowercase() in PROXY_SIDELOAD_DLL_NAMES && !hasAuthenticode) {
            if (matchedApis.isNotEmpty()) {
                score += 25
                indicators.add("Unsigned proxy/sideloaded DLL '$displayName' with high-risk Win32 APIs")
            } else {
                indicators.add("Unsigned proxy DLL '$displayName' (verify if legitimate game/mod loader)")
            }
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
            sizeBytes = fileLen,
            executableSections = execSections,
            suspiciousStrings = (matchedApis + asciiStrings).take(40),
        )

        return ApkThreatFinding(
            id = "pe_${displayName}_${peFile.lastModified()}",
            appName = displayName,
            packageName = "Windows PE ($arch • ${fileLen / (1024 * 1024)} MB)",
            apkPath = peFile.absolutePath,
            source = "Windows PE (.exe/.dll)",
            riskScore = clamped,
            severity = severity,
            maxEntropy = maxEntropy,
            isDebuggable = false,
            dangerousPermissions = matchedApis.map { "win32.api.$it" },
            indicators = indicators,
            suspiciousStrings = (matchedApis + asciiStrings).take(50),
            nativeLibs = listOf(peLibInfo),
            dexCount = 0,
            sha256 = ApkScanner.sha256(peFile),
        )
    }

    /**
     * Streaming surgical PE .text patcher (no file size limit, O(1) RAM).
     */
    fun patchPeBinary(
        inputPe: File,
        outputPe: File,
        instructions: List<AndroidPatchInstruction>,
        passNumber: Int = 1,
    ): List<AndroidPatchRecord> {
        val analysis = analyzePeFile(inputPe, inputPe.name)
        val execSections = analysis?.nativeLibs?.firstOrNull()?.executableSections.orEmpty()
        val arch = analysis?.nativeLibs?.firstOrNull()?.arch ?: "x86_64"
        val records = mutableListOf<AndroidPatchRecord>()

        outputPe.parentFile?.mkdirs()
        // Stream-copy inputPe -> outputPe in 1 MB chunks
        FileInputStream(inputPe).use { inp ->
            FileOutputStream(outputPe).use { out ->
                val buf = ByteArray(STREAM_CHUNK)
                while (true) {
                    val n = inp.read(buf)
                    if (n <= 0) break
                    out.write(buf, 0, n)
                }
            }
        }

        val fileLen = outputPe.length()
        RandomAccessFile(outputPe, "rw").use { raf ->
            val window = ByteArray(64)
            for (inst in instructions) {
                val off = inst.fileOffset
                if (off < 0L || off >= fileLen) continue
                raf.seek(off)
                val readLen = raf.read(window, 0, minOf(64L, fileLen - off).toInt())
                if (readLen <= 0) continue

                val patchBytes = computePePatchBytes(window, readLen, inst.strategy, inst.length) ?: continue
                val inExec = execSections.any { sec ->
                    off >= sec.fileOffset && off + patchBytes.size <= sec.fileOffset + sec.size
                }
                if (!inExec || off + patchBytes.size > fileLen) continue

                val before = window.copyOfRange(0, patchBytes.size)
                if (before.contentEquals(patchBytes)) continue

                raf.seek(off)
                raf.write(patchBytes)
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
        }

        if (records.isNotEmpty()) {
            stripSignatureAndFixChecksumStreaming(outputPe)
        }
        return records
    }

    private fun computePePatchBytes(window: ByteArray, validLen: Int, strategy: String, length: Int): ByteArray? {
        return when (strategy.uppercase().trim()) {
            "RET_EARLY", "RET" -> byteArrayOf(0xC3.toByte())
            "RET_ONE", "RETURN_ONE" -> byteArrayOf(0xB8.toByte(), 0x01, 0x00, 0x00, 0x00, 0xC3.toByte())
            "NOP_SLED", "NOP" -> ByteArray(length.coerceIn(1, 64)) { 0x90.toByte() }
            "FLIP_JUMP", "FLIP_JCC" -> {
                if (validLen < 1) return null
                val b0 = window[0].toInt() and 0xFF
                if (SHORT_JCC_FLIP.containsKey(b0)) {
                    byteArrayOf(SHORT_JCC_FLIP[b0]!!.toByte())
                } else if (b0 == 0x0F && validLen >= 2) {
                    val b1 = window[1].toInt() and 0xFF
                    if (NEAR_JCC_FLIP.containsKey(b1)) {
                        byteArrayOf(0x0F, NEAR_JCC_FLIP[b1]!!.toByte())
                    } else null
                } else null
            }
            else -> byteArrayOf(0x31, 0xC0.toByte(), 0xC3.toByte())
        }
    }

    private fun stripSignatureAndFixChecksumStreaming(peFile: File) {
        RandomAccessFile(peFile, "rw").use { raf ->
            var fileLen = raf.length()
            if (fileLen < 128L) return
            val dos = ByteArray(64)
            raf.seek(0)
            raf.readFully(dos)
            val peOff = ByteBuffer.wrap(dos).order(ByteOrder.LITTLE_ENDIAN).getInt(0x3C).toLong()
            if (peOff < 0L || peOff + 128L > fileLen) return

            val optOff = peOff + 24L
            val magicBuf = ByteArray(2)
            raf.seek(optOff)
            raf.readFully(magicBuf)
            val isPe32Plus = (ByteBuffer.wrap(magicBuf).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF) == 0x20B
            val secDirOff = optOff + (if (isPe32Plus) 112L else 96L) + 32L

            if (secDirOff + 8L <= fileLen) {
                val secDirBuf = ByteArray(8)
                raf.seek(secDirOff)
                raf.readFully(secDirBuf)
                val sbb = ByteBuffer.wrap(secDirBuf).order(ByteOrder.LITTLE_ENDIAN)
                val certOff = sbb.getInt(0).toLong() and 0xFFFFFFFFL
                val certSize = sbb.getInt(4).toLong() and 0xFFFFFFFFL
                if (certOff > 0L && certSize > 0L) {
                    raf.seek(secDirOff)
                    raf.write(ByteArray(8))
                    if (certOff + certSize >= fileLen - 16L && certOff < fileLen) {
                        raf.setLength(certOff)
                        fileLen = certOff
                    }
                }
            }

            // Stream-compute standard Windows PE CheckSum in 1 MB chunks
            val csumOff = optOff + 64L
            if (csumOff + 4L <= fileLen) {
                raf.seek(csumOff)
                raf.write(ByteArray(4))

                raf.seek(0)
                val chunk = ByteArray(STREAM_CHUNK)
                var sum = 0L
                while (true) {
                    val n = raf.read(chunk)
                    if (n <= 0) break
                    var i = 0
                    while (i < n) {
                        val lo = chunk[i].toInt() and 0xFF
                        val hi = if (i + 1 < n) chunk[i + 1].toInt() and 0xFF else 0
                        sum += (lo or (hi shl 8)).toLong()
                        sum = (sum and 0xFFFFL) + (sum ushr 16)
                        i += 2
                    }
                }
                sum = (sum and 0xFFFFL) + (sum ushr 16)
                val finalChecksum = (sum + fileLen).toInt()
                val outBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(finalChecksum).array()
                raf.seek(csumOff)
                raf.write(outBuf)
            }
        }
    }
}
