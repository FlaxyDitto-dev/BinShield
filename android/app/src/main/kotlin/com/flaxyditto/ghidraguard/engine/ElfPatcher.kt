package com.flaxyditto.ghidraguard.engine

import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

data class AndroidPatchInstruction(
    val targetEntry: String, // e.g., "lib/arm64-v8a/libnative.so"
    val functionName: String,
    val fileOffset: Long,
    val strategy: String, // RET_ZERO, RET_EARLY, NOP_SLED
    val length: Int = 8,
    val reason: String = "",
)

data class AndroidPatchRecord(
    val passNumber: Int,
    val targetEntry: String,
    val functionName: String,
    val arch: String,
    val fileOffsetHex: String,
    val strategy: String,
    val beforeHex: String,
    val afterHex: String,
    val reason: String,
)

/**
 * Pure-Kotlin surgical ELF (.so) & APK binary patcher for Android.
 * Supports ARM64 (AArch64), ARMv7, and x86_64 executable sections,
 * and strips invalidated APK signatures when producing a sanitized copy.
 */
object ElfPatcher {

    private const val SHF_EXECINSTR = 0x4L
    private const val EM_ARM = 40
    private const val EM_X86_64 = 62
    private const val EM_AARCH64 = 183

    // ARM64: mov x0, #0; ret  -> 00 00 80 D2 C0 03 5F D6
    private val ARM64_RET_ZERO = byteArrayOf(0x00, 0x00, 0x80.toByte(), 0xD2.toByte(), 0xC0.toByte(), 0x03, 0x5F, 0xD6.toByte())
    // ARM64: ret -> C0 03 5F D6
    private val ARM64_RET_EARLY = byteArrayOf(0xC0.toByte(), 0x03, 0x5F, 0xD6.toByte())
    // ARM64: nop -> 1F 20 03 D5
    private val ARM64_NOP = byteArrayOf(0x1F, 0x20, 0x03, 0xD5.toByte())

    // ARMv7 (ARM mode): mov r0, #0; bx lr -> 00 00 A0 E3 1E FF 2F E1
    private val ARM32_RET_ZERO = byteArrayOf(0x00, 0x00, 0xA0.toByte(), 0xE3.toByte(), 0x1E, 0xFF.toByte(), 0x2F, 0xE1.toByte())
    private val ARM32_RET_EARLY = byteArrayOf(0x1E, 0xFF.toByte(), 0x2F, 0xE1.toByte())
    private val ARM32_NOP = byteArrayOf(0x00, 0xF0.toByte(), 0x20, 0xE3.toByte())

    // x86_64: xor eax, eax; ret -> 31 C0 C3
    private val X64_RET_ZERO = byteArrayOf(0x31, 0xC0.toByte(), 0xC3.toByte())
    private val X64_RET_EARLY = byteArrayOf(0xC3.toByte())

    fun detectElfArch(elfBytes: ByteArray): String {
        if (elfBytes.size < 20) return "unknown"
        if (elfBytes[0] != 0x7F.toByte() || elfBytes[1] != 'E'.code.toByte() ||
            elfBytes[2] != 'L'.code.toByte() || elfBytes[3] != 'F'.code.toByte()
        ) {
            return "not_elf"
        }
        val order = if (elfBytes[5].toInt() == 2) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN
        val machine = ByteBuffer.wrap(elfBytes, 18, 2).order(order).short.toInt() and 0xFFFF
        return when (machine) {
            EM_AARCH64 -> "arm64-v8a"
            EM_ARM -> "armeabi-v7a"
            EM_X86_64 -> "x86_64"
            else -> "elf_machine_$machine"
        }
    }

    fun parseExecutableSections(elfBytes: ByteArray): List<ElfSectionInfo> {
        if (elfBytes.size < 64) return emptyList()
        if (elfBytes[0] != 0x7F.toByte() || elfBytes[1] != 'E'.code.toByte() ||
            elfBytes[2] != 'L'.code.toByte() || elfBytes[3] != 'F'.code.toByte()
        ) {
            return emptyList()
        }
        val is64 = elfBytes[4].toInt() == 2
        val order = if (elfBytes[5].toInt() == 2) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN
        val bb = ByteBuffer.wrap(elfBytes).order(order)

        val sections = mutableListOf<ElfSectionInfo>()
        try {
            if (is64) {
                val eShoff = bb.getLong(40)
                val eShentsize = bb.getShort(58).toInt() and 0xFFFF
                val eShnum = bb.getShort(60).toInt() and 0xFFFF
                if (eShoff <= 0 || eShentsize < 64 || eShnum <= 0) return emptyList()
                for (i in 0 until eShnum) {
                    val off = (eShoff + i.toLong() * eShentsize).toInt()
                    if (off + 64 > elfBytes.size) break
                    val flags = bb.getLong(off + 8)
                    val addr = bb.getLong(off + 16)
                    val secOff = bb.getLong(off + 24)
                    val secSize = bb.getLong(off + 32)
                    val isExec = (flags and SHF_EXECINSTR) != 0L
                    if (isExec && secSize > 0) {
                        sections.add(
                            ElfSectionInfo(
                                name = ".text#$i",
                                fileOffset = secOff,
                                size = secSize,
                                virtualAddress = addr,
                                isExecutable = true,
                            )
                        )
                    }
                }
            } else {
                val eShoff = bb.getInt(32).toLong() and 0xFFFFFFFFL
                val eShentsize = bb.getShort(46).toInt() and 0xFFFF
                val eShnum = bb.getShort(48).toInt() and 0xFFFF
                if (eShoff <= 0 || eShentsize < 40 || eShnum <= 0) return emptyList()
                for (i in 0 until eShnum) {
                    val off = (eShoff + i.toLong() * eShentsize).toInt()
                    if (off + 40 > elfBytes.size) break
                    val flags = bb.getInt(off + 8).toLong() and 0xFFFFFFFFL
                    val addr = bb.getInt(off + 12).toLong() and 0xFFFFFFFFL
                    val secOff = bb.getInt(off + 16).toLong() and 0xFFFFFFFFL
                    val secSize = bb.getInt(off + 20).toLong() and 0xFFFFFFFFL
                    val isExec = (flags and SHF_EXECINSTR) != 0L
                    if (isExec && secSize > 0) {
                        sections.add(
                            ElfSectionInfo(
                                name = ".text#$i",
                                fileOffset = secOff,
                                size = secSize,
                                virtualAddress = addr,
                                isExecutable = true,
                            )
                        )
                    }
                }
            }
        } catch (_: Exception) {
        }
        return sections
    }

    fun computePatchBytes(arch: String, strategy: String, length: Int): ByteArray {
        val strat = strategy.uppercase().trim()
        return when (arch) {
            "arm64-v8a" -> when (strat) {
                "RET_EARLY", "RET" -> ARM64_RET_EARLY
                "NOP_SLED", "NOP" -> {
                    val count = (length / 4).coerceIn(1, 16)
                    ByteArray(count * 4) { i -> ARM64_NOP[i % 4] }
                }
                else -> ARM64_RET_ZERO
            }
            "armeabi-v7a" -> when (strat) {
                "RET_EARLY", "RET" -> ARM32_RET_EARLY
                "NOP_SLED", "NOP" -> {
                    val count = (length / 4).coerceIn(1, 16)
                    ByteArray(count * 4) { i -> ARM32_NOP[i % 4] }
                }
                else -> ARM32_RET_ZERO
            }
            else -> when (strat) {
                "RET_EARLY", "RET" -> X64_RET_EARLY
                "NOP_SLED", "NOP" -> ByteArray(length.coerceIn(1, 32)) { 0x90.toByte() }
                else -> X64_RET_ZERO
            }
        }
    }

    /**
     * Apply surgical ELF patches inside a copy of [inputApk] and write the sanitized
     * APK to [outputApk] (stripping invalidated META-INF signature files).
     */
    fun patchApkNativeLibs(
        inputApk: File,
        outputApk: File,
        instructions: List<AndroidPatchInstruction>,
        passNumber: Int = 1,
    ): List<AndroidPatchRecord> {
        val grouped = instructions.groupBy { it.targetEntry }
        val records = mutableListOf<AndroidPatchRecord>()
        outputApk.parentFile?.mkdirs()

        ZipFile(inputApk).use { zipIn ->
            ZipOutputStream(FileOutputStream(outputApk)).use { zipOut ->
                val entries = zipIn.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    val name = entry.name

                    // Strip invalidated v1 signature artifacts when modifying APK contents
                    if (grouped.isNotEmpty() && name.startsWith("META-INF/") &&
                        (name.endsWith(".RSA") || name.endsWith(".DSA") ||
                            name.endsWith(".EC") || name.endsWith(".SF"))
                    ) {
                        continue
                    }

                    val data = zipIn.getInputStream(entry).use { it.readBytes() }
                    val targetInsts = grouped[name]
                    if (targetInsts != null && targetInsts.isNotEmpty()) {
                        val arch = detectElfArch(data)
                        val execSecs = parseExecutableSections(data)
                        for (inst in targetInsts) {
                            val off = inst.fileOffset.toInt()
                            val patchBytes = computePatchBytes(arch, inst.strategy, inst.length)
                            val inExec = execSecs.isEmpty() || execSecs.any { sec ->
                                inst.fileOffset >= sec.fileOffset &&
                                    inst.fileOffset + patchBytes.size <= sec.fileOffset + sec.size
                            }
                            if (inExec && off >= 0 && off + patchBytes.size <= data.size) {
                                val before = data.copyOfRange(off, off + patchBytes.size)
                                if (!before.contentEquals(patchBytes)) {
                                    patchBytes.copyInto(data, destinationOffset = off)
                                    records.add(
                                        AndroidPatchRecord(
                                            passNumber = passNumber,
                                            targetEntry = name,
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
                        }
                    }

                    val outEntry = ZipEntry(name)
                    zipOut.putNextEntry(outEntry)
                    zipOut.write(data)
                    zipOut.closeEntry()
                }
            }
        }
        return records
    }
}
