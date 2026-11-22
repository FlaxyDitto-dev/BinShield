package com.flaxyditto.ghidraguard.viewmodel

import android.app.Application
import android.content.Context
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.flaxyditto.ghidraguard.engine.AiAuditConfig
import com.flaxyditto.ghidraguard.engine.AiAuditReport
import com.flaxyditto.ghidraguard.engine.AndroidPatchRecord
import com.flaxyditto.ghidraguard.engine.AndroidQuarantineEntry
import com.flaxyditto.ghidraguard.engine.ApkScanner
import com.flaxyditto.ghidraguard.engine.ApkThreatFinding
import com.flaxyditto.ghidraguard.engine.DeviceSecurityCheck
import com.flaxyditto.ghidraguard.engine.ElfPatcher
import com.flaxyditto.ghidraguard.engine.LocalAiAuditor
import com.flaxyditto.ghidraguard.engine.NetworkMonitor
import com.flaxyditto.ghidraguard.engine.NetworkStatusSummary
import com.flaxyditto.ghidraguard.engine.QuarantineVault
import com.flaxyditto.ghidraguard.engine.SocketConnectionInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class GhidraGuardUiState(
    val selectedTab: Int = 0,
    // Scanner
    val isScanning: Boolean = false,
    val scanProgress: Float = 0f,
    val scanStatus: String = "Ready to scan installed apps or inspect a local APK/ELF.",
    val includeSystemApps: Boolean = false,
    val minRiskScore: Int = 15,
    val findings: List<ApkThreatFinding> = emptyList(),
    // Patch Lab
    val activeTarget: ApkThreatFinding? = null,
    val isAuditing: Boolean = false,
    val auditStatus: String = "Idle",
    val auditReports: List<AiAuditReport> = emptyList(),
    val appliedPatches: List<AndroidPatchRecord> = emptyList(),
    val sanitizedApkPath: String = "",
    // Network & Security
    val networkSummary: NetworkStatusSummary? = null,
    val sockets: List<SocketConnectionInfo> = emptyList(),
    val securityChecks: List<DeviceSecurityCheck> = emptyList(),
    // Vault
    val vaultEntries: List<AndroidQuarantineEntry> = emptyList(),
    // Direct On-Device AI Model (Zero Ollama / Zero Server)
    val aiConfig: AiAuditConfig = AiAuditConfig(),
    val localModels: List<File> = emptyList(),
    val aiEngineStatus: String = "Direct On-Device AI: Built-In Analyzer (load a .task/.bin model for LLM)",
    val isLoadingModel: Boolean = false,
    // Terminal Logs
    val logs: List<String> = emptyList(),
)

class GhidraGuardViewModel(application: Application) : AndroidViewModel(application) {

    private val prefs = application.getSharedPreferences("ghidraguard_prefs", Context.MODE_PRIVATE)
    private val vault = QuarantineVault(application)

    private val _uiState = MutableStateFlow(GhidraGuardUiState(aiConfig = loadConfig()))
    val uiState: StateFlow<GhidraGuardUiState> = _uiState.asStateFlow()

    init {
        log("[SYSTEM] GhidraGuard Android v0.2.0 initialized (100% Offline • Direct On-Device AI).")
        refreshLocalModels()
        refreshNetworkAndPosture()
        refreshVault()
    }

    private fun loadConfig(): AiAuditConfig = AiAuditConfig(
        modelPath = prefs.getString("model_path", "") ?: "",
        useGpu = prefs.getBoolean("use_gpu", true),
        maxTokens = prefs.getInt("max_tokens", 2048),
        maxPasses = prefs.getInt("max_passes", 5),
    )

    fun saveConfig(cfg: AiAuditConfig) {
        prefs.edit()
            .putString("model_path", cfg.modelPath)
            .putBoolean("use_gpu", cfg.useGpu)
            .putInt("max_tokens", cfg.maxTokens)
            .putInt("max_passes", cfg.maxPasses)
            .apply()
        val label = if (cfg.modelPath.isNotBlank() && File(cfg.modelPath).isFile) {
            "Direct LLM Ready: ${File(cfg.modelPath).name} (${if (cfg.useGpu) "Mobile GPU" else "CPU"})"
        } else {
            "Direct On-Device AI: Built-In Analyzer (load a .task/.bin model for LLM)"
        }
        _uiState.update { it.copy(aiConfig = cfg, aiEngineStatus = label) }
        log("[SETTINGS] Saved direct on-device AI config (model=${File(cfg.modelPath).name.ifBlank { "built-in" }}, GPU=${cfg.useGpu}).")
    }

    fun refreshLocalModels() {
        viewModelScope.launch(Dispatchers.IO) {
            val found = LocalAiAuditor.discoverLocalModels(getApplication())
            val currentPath = _uiState.value.aiConfig.modelPath
            val selectedPath = when {
                currentPath.isNotBlank() && File(currentPath).isFile -> currentPath
                found.isNotEmpty() -> found.first().absolutePath
                else -> ""
            }
            val updatedCfg = _uiState.value.aiConfig.copy(modelPath = selectedPath)
            val status = if (selectedPath.isNotBlank()) {
                "Direct LLM Ready: ${File(selectedPath).name} (${if (updatedCfg.useGpu) "Mobile GPU" else "CPU"})"
            } else {
                "No .task/.bin model loaded — using built-in analyzer (tap 'Import Local Model' below)"
            }
            _uiState.update {
                it.copy(
                    localModels = found,
                    aiConfig = updatedCfg,
                    aiEngineStatus = status,
                )
            }
        }
    }

    fun importLocalModel(uri: Uri, displayName: String) {
        if (_uiState.value.isLoadingModel) return
        _uiState.update { it.copy(isLoadingModel = true, aiEngineStatus = "Importing $displayName into app storage...") }
        log("[AI] Importing local on-device model file: $displayName...")

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val modelsDir = File(getApplication<Application>().filesDir, "models").apply { mkdirs() }
                val safeName = displayName.replace(Regex("[^a-zA-Z0-9._-]"), "_")
                val dest = File(modelsDir, safeName)
                getApplication<Application>().contentResolver.openInputStream(uri)?.use { inp ->
                    dest.outputStream().use { out -> inp.copyTo(out) }
                }
                val newCfg = _uiState.value.aiConfig.copy(modelPath = dest.absolutePath)
                saveConfig(newCfg)
                refreshLocalModels()
                log("[AI] Imported ${dest.name} (${dest.length() / (1024 * 1024)} MB). Ready for direct on-device inference!")
                _uiState.update { it.copy(isLoadingModel = false) }
            } catch (e: Exception) {
                log("[AI] Model import failed: ${e.message}")
                _uiState.update { it.copy(isLoadingModel = false, aiEngineStatus = "Import failed: ${e.message}") }
            }
        }
    }

    fun preloadSelectedModel() {
        val cfg = _uiState.value.aiConfig
        if (cfg.modelPath.isBlank() || !File(cfg.modelPath).isFile) {
            log("[AI] Import a local .task / .bin model file first to preload into MediaPipe LLM.")
            return
        }
        _uiState.update { it.copy(isLoadingModel = true, aiEngineStatus = "Loading ${File(cfg.modelPath).name} into ${if (cfg.useGpu) "Mobile GPU" else "CPU"}...") }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val msg = LocalAiAuditor.preloadModel(getApplication(), cfg)
                log("[AI] $msg")
                _uiState.update { it.copy(isLoadingModel = false, aiEngineStatus = msg) }
            } catch (e: Exception) {
                log("[AI] Model preload failed: ${e.message}")
                _uiState.update { it.copy(isLoadingModel = false, aiEngineStatus = "Load failed: ${e.message}") }
            }
        }
    }

    fun unloadModel() {
        LocalAiAuditor.unloadModel()
        log("[AI] Unloaded on-device LLM from memory.")
        _uiState.update { it.copy(aiEngineStatus = "Model unloaded from memory (standby).") }
    }

    fun selectTab(index: Int) {
        _uiState.update { it.copy(selectedTab = index) }
        if (index == 2) refreshNetworkAndPosture()
        if (index == 3) refreshVault()
        if (index == 4) refreshLocalModels()
    }

    fun setIncludeSystemApps(include: Boolean) {
        _uiState.update { it.copy(includeSystemApps = include) }
    }

    fun setMinRiskScore(score: Int) {
        _uiState.update { it.copy(minRiskScore = score) }
    }

    fun log(msg: String) {
        val stamp = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        val line = "[$stamp] $msg"
        _uiState.update { st ->
            st.copy(logs = (st.logs + line).takeLast(120))
        }
    }

    fun clearLogs() {
        _uiState.update { it.copy(logs = emptyList()) }
    }

    // -------------------------------------------------------------------------
    // Scanner Actions
    // -------------------------------------------------------------------------

    fun runInstalledAppScan() {
        if (_uiState.value.isScanning) return
        val includeSys = _uiState.value.includeSystemApps
        val minScore = _uiState.value.minRiskScore
        _uiState.update {
            it.copy(isScanning = true, scanProgress = 0.02f, scanStatus = "Enumerating installed packages...")
        }
        log("[SCAN] Starting installed app heuristic scan (systemApps=$includeSys, minScore=$minScore)...")

        viewModelScope.launch(Dispatchers.IO) {
            val results = ApkScanner.scanInstalledApps(
                context = getApplication(),
                includeSystemApps = includeSys,
                minScore = minScore,
            ) { progress, status ->
                _uiState.update { it.copy(scanProgress = progress, scanStatus = status) }
            }
            log("[SCAN] Complete. Found ${results.size} package(s) meeting risk >= $minScore.")
            _uiState.update {
                it.copy(
                    isScanning = false,
                    scanProgress = 1f,
                    scanStatus = "Scan complete: ${results.size} finding(s) (threshold >= $minScore)",
                    findings = results,
                )
            }
        }
    }

    fun inspectPickedApk(uri: Uri, displayName: String) {
        viewModelScope.launch(Dispatchers.IO) {
            log("[SCAN] Importing manual file: $displayName...")
            try {
                val cacheFile = File(getApplication<Application>().cacheDir, "manual_${System.currentTimeMillis()}_$displayName")
                getApplication<Application>().contentResolver.openInputStream(uri)?.use { inp ->
                    cacheFile.outputStream().use { out -> inp.copyTo(out) }
                }
                val finding = ApkScanner.analyzeApkFile(
                    apkFile = cacheFile,
                    appName = displayName,
                    packageName = displayName,
                    source = "Manual APK",
                )
                if (finding != null) {
                    log("[SCAN] Analyzed $displayName -> Risk ${finding.riskScore} (${finding.severity}), Entropy ${finding.maxEntropy}")
                    _uiState.update { st ->
                        st.copy(
                            findings = listOf(finding) + st.findings,
                            scanStatus = "Analyzed $displayName (Risk ${finding.riskScore} / ${finding.severity})",
                        )
                    }
                } else {
                    log("[SCAN] Could not parse $displayName as an APK.")
                }
            } catch (e: Exception) {
                log("[SCAN] Error reading file: ${e.message}")
            }
        }
    }

    fun openInPatchLab(finding: ApkThreatFinding) {
        _uiState.update {
            it.copy(
                activeTarget = finding,
                selectedTab = 1,
                auditReports = emptyList(),
                appliedPatches = emptyList(),
                sanitizedApkPath = "",
                auditStatus = "Target loaded: ${finding.appName}",
            )
        }
        log("[LAB] Loaded ${finding.appName} (${finding.packageName}) into Direct On-Device AI Audit & Patch Lab.")
    }

    // -------------------------------------------------------------------------
    // Direct On-Device AI Audit & Surgical ELF Patching
    // -------------------------------------------------------------------------

    fun runAiAuditAndPatch() {
        val target = _uiState.value.activeTarget ?: return
        if (_uiState.value.isAuditing) return
        val cfg = _uiState.value.aiConfig
        val modelLabel = File(cfg.modelPath).name.ifBlank { "Built-In Analyzer" }

        _uiState.update {
            it.copy(
                isAuditing = true,
                auditStatus = "Running direct on-device audit ($modelLabel)...",
                auditReports = emptyList(),
                appliedPatches = emptyList(),
                sanitizedApkPath = "",
            )
        }
        log("[PIPELINE] Starting Direct On-Device AI Audit on ${target.appName} (model=$modelLabel, GPU=${cfg.useGpu})...")

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val workDir = File(getApplication<Application>().filesDir, "patch_sessions/${System.currentTimeMillis()}").apply { mkdirs() }
                var currentApk = File(workDir, "pass0.apk")
                File(target.apkPath).copyTo(currentApk, overwrite = true)

                val allReports = mutableListOf<AiAuditReport>()
                val allPatches = mutableListOf<AndroidPatchRecord>()
                var currentFinding = target

                val maxPasses = cfg.maxPasses.coerceIn(1, 5)
                for (pass in 1..maxPasses) {
                    log("[PIPELINE] === Pass $pass/$maxPasses ===")
                    val report = LocalAiAuditor.auditApkFinding(
                        context = getApplication(),
                        finding = currentFinding,
                        config = cfg,
                        passNumber = pass,
                        priorPatches = allPatches,
                    )
                    allReports.add(report)
                    _uiState.update {
                        it.copy(
                            auditReports = allReports.toList(),
                            auditStatus = "Pass $pass Verdict: ${report.riskVerdict} [${report.engineUsed}]",
                        )
                    }
                    log("[AI] Pass $pass Verdict: ${report.riskVerdict} (${report.engineUsed})")

                    if (report.isClean || report.patchInstructions.isEmpty()) {
                        break
                    }

                    val nextApk = File(workDir, "pass$pass.apk")
                    val applied = ElfPatcher.patchApkNativeLibs(
                        inputApk = currentApk,
                        outputApk = nextApk,
                        instructions = report.patchInstructions,
                        passNumber = pass,
                    )
                    if (applied.isEmpty()) {
                        log("[PATCH] Pass $pass: 0 verified executable ELF offsets could be patched.")
                        break
                    }
                    allPatches.addAll(applied)
                    applied.forEach { rec ->
                        log("[PATCH] ${rec.targetEntry} @ ${rec.fileOffsetHex} [${rec.beforeHex}] -> [${rec.afterHex}]")
                    }
                    currentApk = nextApk
                    currentFinding = ApkScanner.analyzeApkFile(
                        apkFile = currentApk,
                        appName = target.appName,
                        packageName = target.packageName,
                        source = "Sanitized Pass $pass",
                        requestedPermissions = target.dangerousPermissions,
                        isDebuggable = target.isDebuggable,
                    ) ?: currentFinding

                    _uiState.update {
                        it.copy(
                            appliedPatches = allPatches.toList(),
                            sanitizedApkPath = currentApk.absolutePath,
                        )
                    }
                }

                val finalStatus = allReports.lastOrNull()?.let {
                    "${it.riskVerdict} (${allReports.size} pass(es), ${allPatches.size} ELF patch(es))"
                } ?: "Done"
                _uiState.update { it.copy(isAuditing = false, auditStatus = finalStatus) }
                log("[PIPELINE] Finished: $finalStatus")
            } catch (e: Exception) {
                log("[PIPELINE] Error: ${e.message}")
                _uiState.update { it.copy(isAuditing = false, auditStatus = "Error: ${e.message}") }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Quarantine Vault & Network Monitor
    // -------------------------------------------------------------------------

    fun quarantineFinding(finding: ApkThreatFinding) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val entry = vault.quarantineFile(
                    sourceFile = File(finding.apkPath),
                    displayName = finding.appName,
                    reason = "Risk ${finding.riskScore} (${finding.severity}): ${finding.indicators.firstOrNull() ?: "Manual quarantine"}",
                )
                log("[VAULT] XOR-neutralized & vaulted ${finding.appName} -> ${entry.vaultFilename}")
                refreshVault()
            } catch (e: Exception) {
                log("[VAULT] Quarantine failed: ${e.message}")
            }
        }
    }

    fun restoreVaultEntry(entryId: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val exportDir = File(getApplication<Application>().getExternalFilesDir(null), "restored_apks")
                val out = vault.restoreToExports(entryId, exportDir)
                log("[VAULT] Restored APK to: ${out.absolutePath}")
                refreshVault()
            } catch (e: Exception) {
                log("[VAULT] Restore failed: ${e.message}")
            }
        }
    }

    fun deleteVaultEntry(entryId: String) {
        viewModelScope.launch(Dispatchers.IO) {
            vault.deleteEntry(entryId)
            log("[VAULT] Permanently deleted entry $entryId.")
            refreshVault()
        }
    }

    fun refreshVault() {
        viewModelScope.launch(Dispatchers.IO) {
            val entries = vault.listEntries()
            _uiState.update { it.copy(vaultEntries = entries) }
        }
    }

    fun refreshNetworkAndPosture() {
        viewModelScope.launch(Dispatchers.IO) {
            val summary = NetworkMonitor.getNetworkSummary(getApplication())
            val sockets = NetworkMonitor.readActiveSockets()
            val checks = NetworkMonitor.runDeviceSecurityPosture(getApplication())
            _uiState.update {
                it.copy(
                    networkSummary = summary,
                    sockets = sockets,
                    securityChecks = checks,
                )
            }
        }
    }
}
