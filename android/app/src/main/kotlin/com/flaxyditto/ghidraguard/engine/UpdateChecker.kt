package com.flaxyditto.ghidraguard.engine

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

data class AndroidUpdateInfo(
    val currentVersion: String,
    val latestVersion: String,
    val updateAvailable: Boolean,
    val releaseUrl: String,
    val downloadUrl: String = "",
    val error: String? = null,
)

/**
 * Automatic GitHub Releases update checker for GhidraGuard Android Edition.
 */
object UpdateChecker {
    const val CURRENT_VERSION = "2.0.0"
    private const val API_URL = "https://api.github.com/repos/FlaxyDitto-dev/GhidraGuard/releases/latest"

    fun checkLatestRelease(): AndroidUpdateInfo {
        return try {
            val conn = (URL(API_URL).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = 8000
                readTimeout = 8000
                setRequestProperty("User-Agent", "GhidraGuard-Android/$CURRENT_VERSION")
                setRequestProperty("Accept", "application/vnd.github+json")
            }
            val body = conn.inputStream.bufferedReader().use { it.readText() }
            val json = JSONObject(body)
            val tag = json.optString("tag_name", CURRENT_VERSION).trimStart('v', 'V')
            val htmlUrl = json.optString("html_url", "https://github.com/FlaxyDitto-dev/GhidraGuard/releases")
            var apkUrl = ""
            val assets = json.optJSONArray("assets")
            if (assets != null) {
                for (i in 0 until assets.length()) {
                    val a = assets.getJSONObject(i)
                    if (a.optString("name", "").endsWith(".apk", ignoreCase = true)) {
                        apkUrl = a.optString("browser_download_url", "")
                        break
                    }
                }
            }
            AndroidUpdateInfo(
                currentVersion = CURRENT_VERSION,
                latestVersion = tag,
                updateAvailable = compareSemVer(tag, CURRENT_VERSION) > 0,
                releaseUrl = htmlUrl,
                downloadUrl = apkUrl,
            )
        } catch (e: Exception) {
            AndroidUpdateInfo(
                currentVersion = CURRENT_VERSION,
                latestVersion = CURRENT_VERSION,
                updateAvailable = false,
                releaseUrl = "https://github.com/FlaxyDitto-dev/GhidraGuard/releases",
                error = e.message,
            )
        }
    }

    internal fun compareSemVer(a: String, b: String): Int {
        val pa = a.substringBefore('-').split('.').map { it.toIntOrNull() ?: 0 }
        val pb = b.substringBefore('-').split('.').map { it.toIntOrNull() ?: 0 }
        for (i in 0..2) {
            val diff = (pa.getOrElse(i) { 0 }) - (pb.getOrElse(i) { 0 })
            if (diff != 0) return diff
        }
        return 0
    }
}
