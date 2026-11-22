package com.flaxyditto.ghidraguard.engine

import android.content.Context
import com.google.mediapipe.tasks.genai.llminference.LlmInference
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

data class AiAuditConfig(
    val modelPath: String = "",
    val useGpu: Boolean = true,
    val maxTokens: Int = 2048,
    val maxPasses: Int = 5,
)

data class AiAuditReport(
    val passNumber: Int,
    val isClean: Boolean,
    val riskVerdict: String, // CLEAN, SUSPICIOUS, MALICIOUS, PACKED
    val summary: String,
    val findings: List<String>,
    val recommendedActions: List<String>,
    val patchInstructions: List<AndroidPatchInstruction>,
    val rawResponse: String,
    val engineUsed: String = "On-Device",
)

/**
 * Direct On-Device AI Auditor for Android (Zero Ollama, Zero HTTP Server, Zero Internet).
 *
 * Uses Google MediaPipe `LlmInference` (GPU / CPU) to load and execute local quantized
 * `.task` / `.litertlm` / `.bin` LLM models directly inside the app process.
 * If no model file has been loaded yet, falls back to a built-in deterministic
 * on-device static security analyzer so the Audit Lab works immediately out of the box.
 */
object LocalAiAuditor {

    @Volatile
    private var cachedInference: LlmInference? = null

    @Volatile
    private var cachedKey: String = ""

    private const val ANDROID_SYSTEM_PROMPT = """You are an expert Reverse Engineer and Malware Analyst auditing either an Android APK (permissions, DEX strings, native ELF .so sections) OR a Windows PE binary (.exe/.dll sections, Win32 APIs, entropy, strings).
Respond ONLY with valid JSON matching this exact schema (no markdown fences, no extra prose):
{
  "is_clean": false,
  "risk_verdict": "CLEAN | SUSPICIOUS | MALICIOUS | PACKED",
  "summary": "Concise security verdict.",
  "findings": ["Finding 1", "Finding 2"],
  "recommended_actions": ["Action 1", "Action 2"],
  "elf_patches": []
}"""

    fun discoverLocalModels(context: Context): List<File> {
        val dirs = listOfNotNull(
            File(context.filesDir, "models").apply { mkdirs() },
            context.getExternalFilesDir("models")?.apply { mkdirs() },
        )
        val out = mutableListOf<File>()
        for (dir in dirs) {
            dir.listFiles()?.forEach { f ->
                if (f.isFile && (f.name.endsWith(".task", true) ||
                        f.name.endsWith(".bin", true) ||
                        f.name.endsWith(".litertlm", true))
                ) {
                    out.add(f)
                }
            }
        }
        return out.sortedBy { it.name }
    }

    @Synchronized
    fun unloadModel() {
        try {
            cachedInference?.close()
        } catch (_: Exception) {
        }
        cachedInference = null
        cachedKey = ""
    }

    @Synchronized
    private fun getOrCreateInference(context: Context, config: AiAuditConfig): LlmInference {
        val modelFile = File(config.modelPath)
        require(modelFile.isFile && modelFile.canRead()) {
            "Local AI model file not found or unreadable: ${config.modelPath}"
        }
        val key = "${modelFile.absolutePath}|${config.useGpu}|${config.maxTokens}"
        val existing = cachedInference
        if (existing != null && cachedKey == key) {
            return existing
        }
        unloadModel()

        val backend = if (config.useGpu) LlmInference.Backend.GPU else LlmInference.Backend.CPU
        val options = LlmInference.LlmInferenceOptions.builder()
            .setModelPath(modelFile.absolutePath)
            .setMaxTokens(config.maxTokens.coerceIn(512, 4096))
            .setPreferredBackend(backend)
            .build()

        val instance = try {
            LlmInference.createFromOptions(context.applicationContext, options)
        } catch (gpuErr: Exception) {
            if (config.useGpu) {
                // Automatic CPU fallback if mobile GPU delegate is unavailable
                val cpuOpts = LlmInference.LlmInferenceOptions.builder()
                    .setModelPath(modelFile.absolutePath)
                    .setMaxTokens(config.maxTokens.coerceIn(512, 4096))
                    .setPreferredBackend(LlmInference.Backend.CPU)
                    .build()
                LlmInference.createFromOptions(context.applicationContext, cpuOpts)
            } else {
                throw gpuErr
            }
        }

        cachedInference = instance
        cachedKey = key
        return instance
    }

    fun preloadModel(context: Context, config: AiAuditConfig): String {
        val llm = getOrCreateInference(context, config)
        val name = File(config.modelPath).name
        val accel = if (config.useGpu) "Mobile GPU" else "CPU"
        return "Loaded $name directly on-device ($accel) [${llm.hashCode()}]"
    }

    fun auditApkFinding(
        context: Context,
        finding: ApkThreatFinding,
        config: AiAuditConfig,
        passNumber: Int = 1,
        priorPatches: List<AndroidPatchRecord> = emptyList(),
    ): AiAuditReport {
        val modelFile = if (config.modelPath.isNotBlank()) File(config.modelPath) else null
        if (modelFile == null || !modelFile.isFile) {
            return runBuiltInHeuristicAudit(finding, passNumber)
        }

        val llm = getOrCreateInference(context, config)
        val fullPrompt = "$ANDROID_SYSTEM_PROMPT\n\n${buildAuditPrompt(finding, passNumber, priorPatches)}"
        val rawText = llm.generateResponse(fullPrompt)
        val parsed = extractJsonObject(rawText)

        val isClean = parsed.optBoolean("is_clean", false)
        val verdict = parsed.optString("risk_verdict", if (isClean) "CLEAN" else "SUSPICIOUS")
        val summary = parsed.optString("summary", "Direct on-device LLM audit completed.")

        val findingsList = mutableListOf<String>()
        val fArr = parsed.optJSONArray("findings") ?: JSONArray()
        for (i in 0 until fArr.length()) {
            findingsList.add(fArr.optString(i))
        }

        val actionsList = mutableListOf<String>()
        val aArr = parsed.optJSONArray("recommended_actions") ?: JSONArray()
        for (i in 0 until aArr.length()) {
            actionsList.add(aArr.optString(i))
        }

        val patches = mutableListOf<AndroidPatchInstruction>()
        val pArr = parsed.optJSONArray("elf_patches") ?: JSONArray()
        for (i in 0 until pArr.length()) {
            val pObj = pArr.optJSONObject(i) ?: continue
            val entry = pObj.optString("target_entry", "")
            val off = parseHexOrDec(pObj.optString("file_offset", "").trim())
            if (entry.isNotBlank() && off >= 0) {
                patches.add(
                    AndroidPatchInstruction(
                        targetEntry = entry,
                        functionName = pObj.optString("function_name", "native_fn"),
                        fileOffset = off,
                        strategy = pObj.optString("strategy", "RET_ZERO"),
                        length = pObj.optInt("length", 8),
                        reason = pObj.optString("reason", "Neutralize malicious native routine"),
                    )
                )
            }
        }

        return AiAuditReport(
            passNumber = passNumber,
            isClean = isClean,
            riskVerdict = verdict,
            summary = summary,
            findings = findingsList,
            recommendedActions = actionsList,
            patchInstructions = patches,
            rawResponse = rawText,
            engineUsed = "Direct On-Device LLM (${modelFile.name} • ${if (config.useGpu) "GPU" else "CPU"})",
        )
    }

    private fun runBuiltInHeuristicAudit(finding: ApkThreatFinding, passNumber: Int): AiAuditReport {
        val isClean = finding.riskScore < 25 && finding.indicators.isEmpty()
        val verdict = when {
            finding.maxEntropy >= 7.3 -> "PACKED"
            finding.riskScore >= 70 -> "MALICIOUS"
            finding.riskScore >= 30 -> "SUSPICIOUS"
            else -> "CLEAN"
        }
        val actions = mutableListOf<String>()
        if (finding.dangerousPermissions.isNotEmpty()) {
            actions.add("Revoke high-risk permissions in Android Settings: ${finding.dangerousPermissions.take(4).joinToString { it.substringAfterLast('.') }}")
        }
        if (finding.maxEntropy >= 7.2) {
            actions.add("High entropy (${finding.maxEntropy}) indicates possible packed/encrypted DEX or native library; quarantine copy before execution.")
        }
        if (finding.isDebuggable) {
            actions.add("Package has FLAG_DEBUGGABLE enabled — avoid storing sensitive credentials in this app.")
        }
        actions.add("Load a local .task/.bin LLM model in the Engines tab to enable full generative on-device AI reasoning.")

        return AiAuditReport(
            passNumber = passNumber,
            isClean = isClean,
            riskVerdict = verdict,
            summary = "Built-in on-device static analyzer verdict: $verdict (Risk ${finding.riskScore}/100, ${finding.indicators.size} indicator(s)).",
            findings = if (finding.indicators.isNotEmpty()) finding.indicators else listOf("No high-risk static malware indicators detected."),
            recommendedActions = actions,
            patchInstructions = emptyList(),
            rawResponse = "Built-in on-device analyzer (no .task LLM file loaded yet).",
            engineUsed = "Built-In On-Device Heuristic Analyzer",
        )
    }

    private fun buildAuditPrompt(
        f: ApkThreatFinding,
        passNumber: Int,
        priorPatches: List<AndroidPatchRecord>,
    ): String = buildString {
        appendLine("=== ANDROID APK AUDIT PASS $passNumber ===")
        appendLine("App: ${f.appName} (${f.packageName})")
        appendLine("RiskScore: ${f.riskScore}/100 (${f.severity}) | MaxEntropy: ${f.maxEntropy} | DEX: ${f.dexCount}")
        if (f.dangerousPermissions.isNotEmpty()) {
            appendLine("Dangerous Permissions: ${f.dangerousPermissions.take(10).joinToString { it.substringAfterLast('.') }}")
        }
        if (f.indicators.isNotEmpty()) {
            appendLine("Indicators: ${f.indicators.joinToString("; ")}")
        }
        if (f.suspiciousStrings.isNotEmpty()) {
            appendLine("Suspicious Strings: ${f.suspiciousStrings.take(18).joinToString(", ")}")
        }
        if (f.nativeLibs.isNotEmpty()) {
            appendLine("Native ELF Libs:")
            f.nativeLibs.take(4).forEach { lib ->
                val secs = lib.executableSections.take(3).joinToString { "${it.name}@0x${it.fileOffset.toString(16)}" }
                appendLine("  - ${lib.entryPath} [${lib.arch}] ent=${lib.entropy} exec=[$secs]")
            }
        }
        if (priorPatches.isNotEmpty()) {
            appendLine("Prior Patches: ${priorPatches.size}")
        }
        appendLine("Return ONLY valid JSON.")
    }

    private fun extractJsonObject(raw: String): JSONObject {
        val cleaned = raw.trim()
        val start = cleaned.indexOf('{')
        val end = cleaned.lastIndexOf('}')
        if (start != -1 && end > start) {
            return try {
                JSONObject(cleaned.substring(start, end + 1))
            } catch (_: Exception) {
                JSONObject().put("is_clean", false).put("risk_verdict", "SUSPICIOUS").put("summary", cleaned.take(400))
            }
        }
        return JSONObject().put("is_clean", false).put("risk_verdict", "SUSPICIOUS").put("summary", cleaned.take(400))
    }

    private fun parseHexOrDec(s: String): Long {
        if (s.isBlank()) return -1L
        return try {
            if (s.startsWith("0x", ignoreCase = true)) s.substring(2).toLong(16)
            else s.toLong()
        } catch (_: Exception) {
            -1L
        }
    }
}
