package com.flaxyditto.ghidraguard.engine

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

data class AndroidQuarantineEntry(
    val entryId: String,
    val displayName: String,
    val originalPath: String,
    val vaultFilename: String,
    val sha256: String,
    val reason: String,
    val timestamp: String,
    val sizeBytes: Long,
)

/**
 * XOR-Neutralized Quarantine Vault matching desktop BinShield (0x5A XOR on first 4KB).
 * Stores neutralized APK/ELF artifacts inside app-private filesDir/quarantine.
 */
class QuarantineVault(context: Context) {

    private val vaultDir = File(context.filesDir, "quarantine").apply { mkdirs() }
    private val manifestFile = File(vaultDir, "vault.json")
    private val xorKey: Byte = 0x5A

    fun listEntries(): List<AndroidQuarantineEntry> {
        if (!manifestFile.isFile) return emptyList()
        return try {
            val arr = JSONArray(manifestFile.readText())
            (0 until arr.length()).mapNotNull { i ->
                val o = arr.optJSONObject(i) ?: return@mapNotNull null
                AndroidQuarantineEntry(
                    entryId = o.optString("entryId"),
                    displayName = o.optString("displayName"),
                    originalPath = o.optString("originalPath"),
                    vaultFilename = o.optString("vaultFilename"),
                    sha256 = o.optString("sha256"),
                    reason = o.optString("reason"),
                    timestamp = o.optString("timestamp"),
                    sizeBytes = o.optLong("sizeBytes"),
                )
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun saveEntries(entries: List<AndroidQuarantineEntry>) {
        val arr = JSONArray()
        entries.forEach { e ->
            arr.put(
                JSONObject().apply {
                    put("entryId", e.entryId)
                    put("displayName", e.displayName)
                    put("originalPath", e.originalPath)
                    put("vaultFilename", e.vaultFilename)
                    put("sha256", e.sha256)
                    put("reason", e.reason)
                    put("timestamp", e.timestamp)
                    put("sizeBytes", e.sizeBytes)
                }
            )
        }
        manifestFile.writeText(arr.toString(2))
    }

    fun quarantineFile(sourceFile: File, displayName: String, reason: String): AndroidQuarantineEntry {
        require(sourceFile.isFile && sourceFile.canRead()) { "Cannot read file: ${sourceFile.absolutePath}" }
        val sha = ApkScanner.sha256(sourceFile)
        val entryId = UUID.randomUUID().toString().replace("-", "").take(12)
        val safeName = displayName.replace(Regex("[^a-zA-Z0-9._-]"), "_")
        val vaultFilename = "${entryId}_${safeName}.ggquar"
        val vaultFile = File(vaultDir, vaultFilename)

        // Stream-copy in 1 MB chunks while XOR-neutralizing first 4KB (no file size limit)
        var written = 0L
        val buf = ByteArray(1024 * 1024)
        sourceFile.inputStream().use { inp ->
            vaultFile.outputStream().use { out ->
                while (true) {
                    val n = inp.read(buf)
                    if (n <= 0) break
                    if (written < 4096L) {
                        val limit = minOf((4096L - written).toInt(), n)
                        for (i in 0 until limit) {
                            buf[i] = (buf[i].toInt() xor xorKey.toInt()).toByte()
                        }
                    }
                    out.write(buf, 0, n)
                    written += n
                }
            }
        }

        val stamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
        val entry = AndroidQuarantineEntry(
            entryId = entryId,
            displayName = displayName,
            originalPath = sourceFile.absolutePath,
            vaultFilename = vaultFilename,
            sha256 = sha,
            reason = reason,
            timestamp = stamp,
            sizeBytes = written,
        )
        val all = listEntries().toMutableList()
        all.add(0, entry)
        saveEntries(all)
        return entry
    }

    fun restoreToExports(entryId: String, exportDir: File): File {
        val entries = listEntries().toMutableList()
        val target = entries.firstOrNull { it.entryId == entryId }
            ?: throw IllegalArgumentException("Quarantine entry not found: $entryId")
        val vaultFile = File(vaultDir, target.vaultFilename)
        require(vaultFile.isFile) { "Vault payload missing: ${target.vaultFilename}" }

        exportDir.mkdirs()
        val ext = File(target.displayName).extension.ifBlank { "apk" }
        val base = File(target.displayName).nameWithoutExtension.ifBlank { target.displayName }
        val outFile = File(exportDir, "${base}_restored.$ext")

        // Stream-restore in 1 MB chunks while un-XORing first 4KB (no file size limit)
        var written = 0L
        val buf = ByteArray(1024 * 1024)
        vaultFile.inputStream().use { inp ->
            outFile.outputStream().use { out ->
                while (true) {
                    val n = inp.read(buf)
                    if (n <= 0) break
                    if (written < 4096L) {
                        val limit = minOf((4096L - written).toInt(), n)
                        for (i in 0 until limit) {
                            buf[i] = (buf[i].toInt() xor xorKey.toInt()).toByte()
                        }
                    }
                    out.write(buf, 0, n)
                    written += n
                }
            }
        }
        vaultFile.delete()
        entries.removeAll { it.entryId == entryId }
        saveEntries(entries)
        return outFile
    }

    fun deleteEntry(entryId: String) {
        val entries = listEntries().toMutableList()
        val target = entries.firstOrNull { it.entryId == entryId } ?: return
        File(vaultDir, target.vaultFilename).delete()
        entries.removeAll { it.entryId == entryId }
        saveEntries(entries)
    }
}
