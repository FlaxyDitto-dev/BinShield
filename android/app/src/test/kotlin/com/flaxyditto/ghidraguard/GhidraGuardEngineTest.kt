package com.flaxyditto.ghidraguard

import com.flaxyditto.ghidraguard.engine.AndroidPatchInstruction
import com.flaxyditto.ghidraguard.engine.ApkScanner
import com.flaxyditto.ghidraguard.engine.ElfPatcher
import com.flaxyditto.ghidraguard.engine.PeAnalyzerPatcher
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.zip.ZipFile

class GhidraGuardEngineTest {

    @Test
    fun verifyRealWindowsPeAnalysisAndSurgicalPatching() {
        val sample = File("C:\\Users\\johna\\.gemini\\antigravity\\scratch\\BinShield\\test_samples\\mock_threat_sample.exe")
        if (!sample.isFile) {
            println("Skipping external sample test (mock_threat_sample.exe not present)")
            return
        }

        assertTrue("Should detect MZ/PE magic", PeAnalyzerPatcher.isPeFile(sample))
        val finding = PeAnalyzerPatcher.analyzePeFile(sample, sample.name)
        assertNotNull("PE analysis must succeed on real .exe", finding)
        finding!!

        println("Android PE Analyzer -> ${finding.appName} | ${finding.packageName} | Risk=${finding.riskScore} (${finding.severity}) | Entropy=${finding.maxEntropy}")
        assertTrue("Should detect Windows PE source", finding.source.startsWith("Windows PE"))
        assertTrue("Should find executable .text section", finding.nativeLibs.first().executableSections.isNotEmpty())
        assertTrue("Should detect suspicious Win32 APIs", finding.indicators.isNotEmpty())

        val textSec = finding.nativeLibs.first().executableSections.first()
        val outPe = File.createTempFile("gg_android_pe_patch_", ".exe")
        try {
            val recs = PeAnalyzerPatcher.patchPeBinary(
                inputPe = sample,
                outputPe = outPe,
                instructions = listOf(
                    AndroidPatchInstruction(
                        targetEntry = sample.name,
                        functionName = "test_target_fn",
                        fileOffset = textSec.fileOffset,
                        strategy = "RET_ZERO",
                        length = 3,
                        reason = "Unit test surgical RET_ZERO",
                    )
                ),
                passNumber = 1,
            )
            assertEquals("Should apply 1 real PE patch", 1, recs.size)
            assertEquals("31 C0 C3", recs[0].afterHex)

            val patchedBytes = outPe.readBytes()
            val off = textSec.fileOffset.toInt()
            assertEquals(0x31.toByte(), patchedBytes[off])
            assertEquals(0xC0.toByte(), patchedBytes[off + 1])
            assertEquals(0xC3.toByte(), patchedBytes[off + 2])
            println("Android PE Patcher verified bytes on disk at 0x${off.toString(16)}: ${recs[0].beforeHex} -> ${recs[0].afterHex}")
        } finally {
            outPe.delete()
        }
    }

    @Test
    fun verifyRealApkAndNativeElfInspection() {
        val apk = File("C:\\Users\\johna\\.gemini\\antigravity\\scratch\\BinShield\\BinShield-v0.2.0-direct-ai.apk")
        if (!apk.isFile) {
            println("Skipping real APK test (APK not built yet)")
            return
        }

        val finding = ApkScanner.analyzeApkFile(apk, apk.name, "com.flaxyditto.ghidraguard", "Real Built APK")
        assertNotNull("APK analysis must succeed", finding)
        finding!!

        println("Android APK Analyzer -> DEX=${finding.dexCount} | NativeLibs=${finding.nativeLibs.size} | MaxEntropy=${finding.maxEntropy} | SHA256=${finding.sha256.take(16)}...")
        assertTrue("Built APK must contain DEX files", finding.dexCount >= 1)
        assertTrue("Built APK must contain native ELF .so libs (MediaPipe LLM runtime)", finding.nativeLibs.isNotEmpty())
        assertTrue("SHA-256 must be 64 hex chars", finding.sha256.length == 64)

        // Verify ELF parser on a real .so inside the APK
        val firstSo = finding.nativeLibs.first()
        ZipFile(apk).use { zip ->
            val entry = zip.getEntry(firstSo.entryPath)
            assertNotNull(entry)
            val elfBytes = zip.getInputStream(entry).use { it.readBytes() }
            val arch = ElfPatcher.detectElfArch(elfBytes)
            assertTrue("Should detect real ELF arch, got $arch", arch == "arm64-v8a" || arch == "armeabi-v7a" || arch == "x86_64")
            println("Android ELF Parser verified real .so: ${firstSo.entryPath} -> arch=$arch")
        }
    }
}
