package com.flaxyditto.ghidraguard.ui.screens

import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.io.File
import com.flaxyditto.ghidraguard.ui.theme.AccentAmber
import com.flaxyditto.ghidraguard.ui.theme.AccentCyan
import com.flaxyditto.ghidraguard.ui.theme.AccentGreen
import com.flaxyditto.ghidraguard.ui.theme.AccentPurple
import com.flaxyditto.ghidraguard.ui.theme.AccentRed
import com.flaxyditto.ghidraguard.ui.theme.BgCard
import com.flaxyditto.ghidraguard.ui.theme.BgCardAlt
import com.flaxyditto.ghidraguard.ui.theme.BgInput
import com.flaxyditto.ghidraguard.ui.theme.BgRoot
import com.flaxyditto.ghidraguard.ui.theme.BorderAccent
import com.flaxyditto.ghidraguard.ui.theme.BorderGlass
import com.flaxyditto.ghidraguard.ui.theme.TextMuted
import com.flaxyditto.ghidraguard.ui.theme.TextPrimary
import com.flaxyditto.ghidraguard.ui.theme.TextSecondary
import com.flaxyditto.ghidraguard.viewmodel.GhidraGuardUiState
import com.flaxyditto.ghidraguard.viewmodel.GhidraGuardViewModel

@Composable
fun NetworkScreen(
    state: GhidraGuardUiState,
    vm: GhidraGuardViewModel,
) {
    val scroll = rememberScrollState()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scroll)
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Card(
            colors = CardDefaults.cardColors(containerColor = BgCard),
            border = BorderStroke(1.dp, BorderGlass),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("Live Network & Device Posture", color = TextPrimary, fontSize = 17.sp, fontWeight = FontWeight.Bold)
                    Button(
                        onClick = { vm.refreshNetworkAndPosture() },
                        colors = ButtonDefaults.buttonColors(containerColor = AccentCyan, contentColor = BgRoot),
                    ) {
                        Text("Refresh", fontWeight = FontWeight.Bold)
                    }
                }

                val net = state.networkSummary
                if (net != null) {
                    Text(
                        text = buildString {
                            appendLine("Transport : ${net.transport} | Validated: ${net.isValidated} | VPN: ${if (net.isVpnActive) "ACTIVE" else "OFF"}")
                            appendLine("Local IPs : ${net.localAddresses.joinToString().ifBlank { "None" }}")
                            append("DNS       : ${net.dnsServers.joinToString().ifBlank { "None" }}")
                        },
                        color = BorderAccent,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(BgInput, RoundedCornerShape(8.dp))
                            .padding(10.dp),
                    )
                }
            }
        }

        // Device Security Posture
        Card(
            colors = CardDefaults.cardColors(containerColor = BgCard),
            border = BorderStroke(1.dp, BorderGlass),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Device Security Checks", color = BorderAccent, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                state.securityChecks.forEach { chk ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(BgCardAlt, RoundedCornerShape(8.dp))
                            .padding(10.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(chk.title, color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                            Text(chk.detail, color = TextSecondary, fontSize = 11.sp)
                        }
                        Box(
                            modifier = Modifier
                                .background(if (chk.isSafe) AccentGreen else AccentAmber, RoundedCornerShape(6.dp))
                                .padding(horizontal = 8.dp, vertical = 3.dp)
                        ) {
                            Text(chk.status, color = BgRoot, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }

        // Active Sockets (/proc/net/tcp & udp)
        Card(
            colors = CardDefaults.cardColors(containerColor = BgCard),
            border = BorderStroke(1.dp, BorderGlass),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Active Sockets (${state.sockets.size})", color = AccentCyan, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                if (state.sockets.isEmpty()) {
                    Text(
                        "Android 10+ restricts unprivileged /proc/net/tcp access. Active interface & DNS posture is shown above.",
                        color = TextMuted,
                        fontSize = 12.sp,
                    )
                } else {
                    state.sockets.take(40).forEach { s ->
                        Text(
                            text = "[${s.protocol}] UID ${s.uid} | ${s.localAddr} -> ${s.remoteAddr} (${s.state})",
                            color = if (s.isExternal) AccentAmber else TextSecondary,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(BgInput, RoundedCornerShape(6.dp))
                                .padding(6.dp),
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun VaultScreen(
    state: GhidraGuardUiState,
    vm: GhidraGuardViewModel,
) {
    val scroll = rememberScrollState()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scroll)
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Card(
            colors = CardDefaults.cardColors(containerColor = BgCard),
            border = BorderStroke(1.dp, BorderGlass),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("XOR-Neutralized Quarantine Vault", color = TextPrimary, fontSize = 17.sp, fontWeight = FontWeight.Bold)
                Text(
                    "Samples are neutralized with 0x5A XOR on their first 4KB header (matching desktop GhidraGuard) so they cannot execute or install.",
                    color = TextSecondary,
                    fontSize = 12.sp,
                )
            }
        }

        if (state.vaultEntries.isEmpty()) {
            Card(
                colors = CardDefaults.cardColors(containerColor = BgCard),
                border = BorderStroke(1.dp, BorderGlass),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Box(modifier = Modifier.padding(32.dp).fillMaxWidth(), contentAlignment = Alignment.Center) {
                    Text("Quarantine Vault is empty.", color = TextMuted, fontSize = 13.sp)
                }
            }
        } else {
            state.vaultEntries.forEach { e ->
                Card(
                    colors = CardDefaults.cardColors(containerColor = BgCardAlt),
                    border = BorderStroke(1.dp, BorderGlass),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(e.displayName, color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                        Text(
                            text = "SHA256: ${e.sha256.take(28)}...\nTime: ${e.timestamp} | Size: ${e.sizeBytes / 1024} KB\nReason: ${e.reason}",
                            color = TextSecondary,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = { vm.restoreVaultEntry(e.entryId) },
                                colors = ButtonDefaults.buttonColors(containerColor = AccentGreen, contentColor = BgRoot),
                            ) {
                                Text("Restore Export", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                            }
                            Button(
                                onClick = { vm.deleteVaultEntry(e.entryId) },
                                colors = ButtonDefaults.buttonColors(containerColor = AccentRed, contentColor = TextPrimary),
                            ) {
                                Text("Delete", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun SettingsScreen(
    state: GhidraGuardUiState,
    vm: GhidraGuardViewModel,
) {
    val context = LocalContext.current
    val cfg = state.aiConfig
    var useGpu by remember(cfg.useGpu) { mutableStateOf(cfg.useGpu) }
    var selectedPath by remember(cfg.modelPath) { mutableStateOf(cfg.modelPath) }

    val modelPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            var name = "local_model.task"
            context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (idx >= 0 && cursor.moveToFirst()) {
                    name = cursor.getString(idx) ?: name
                }
            }
            vm.importLocalModel(uri, name)
        }
    }

    val scroll = rememberScrollState()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scroll)
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        // Direct On-Device AI Engine Card (Zero Ollama / Zero Server)
        Card(
            colors = CardDefaults.cardColors(containerColor = BgCard),
            border = BorderStroke(1.dp, BorderGlass),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Direct On-Device AI Model (Zero Ollama / 100% Offline)",
                    color = TextPrimary,
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    "Runs quantized MediaPipe / LiteRT LLM models (.task, .litertlm, .bin) directly on your phone's GPU or CPU with zero external server and zero internet permission.",
                    color = TextSecondary,
                    fontSize = 12.sp,
                )

                Text(state.aiEngineStatus, color = BorderAccent, fontSize = 12.sp, fontWeight = FontWeight.Bold)

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                    Button(
                        onClick = { modelPicker.launch(arrayOf("*/*")) },
                        enabled = !state.isLoadingModel,
                        colors = ButtonDefaults.buttonColors(containerColor = AccentPurple, contentColor = TextPrimary),
                        modifier = Modifier.weight(1f),
                    ) {
                        Text("Import .task / .bin Model", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    }
                    OutlinedButton(
                        onClick = { vm.refreshLocalModels() },
                        border = BorderStroke(1.dp, BorderAccent),
                    ) {
                        Text("Scan", color = BorderAccent, fontSize = 12.sp)
                    }
                }

                if (state.localModels.isNotEmpty()) {
                    Text("Installed On-Device Models:", color = TextSecondary, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    state.localModels.forEach { file ->
                        val isSel = file.absolutePath == selectedPath
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(if (isSel) BgCardAlt else BgInput, RoundedCornerShape(8.dp))
                                .padding(horizontal = 10.dp, vertical = 8.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(file.name, color = if (isSel) BorderAccent else TextPrimary, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                                Text("${file.length() / (1024 * 1024)} MB", color = TextMuted, fontFamily = FontFamily.Monospace, fontSize = 10.sp)
                            }
                            OutlinedButton(
                                onClick = {
                                    selectedPath = file.absolutePath
                                    vm.saveConfig(cfg.copy(modelPath = file.absolutePath, useGpu = useGpu))
                                },
                                border = BorderStroke(1.dp, if (isSel) AccentGreen else BorderGlass),
                            ) {
                                Text(if (isSel) "Active" else "Select", color = if (isSel) AccentGreen else TextSecondary, fontSize = 11.sp)
                            }
                        }
                    }
                } else {
                    Text(
                        "Active Model: Built-In On-Device Static Analyzer (import a Gemma/Qwen .task model to enable generative on-device LLM reasoning).",
                        color = TextMuted,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(BgInput, RoundedCornerShape(8.dp))
                            .padding(8.dp),
                    )
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = useGpu,
                        onCheckedChange = {
                            useGpu = it
                            vm.saveConfig(cfg.copy(modelPath = selectedPath, useGpu = it))
                        },
                        colors = CheckboxDefaults.colors(checkedColor = AccentCyan),
                    )
                    Text("Use Mobile GPU Acceleration (OpenCL / Vulkan, auto-fallback to CPU)", color = TextPrimary, fontSize = 12.sp)
                }

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                    Button(
                        onClick = { vm.preloadSelectedModel() },
                        enabled = selectedPath.isNotBlank() && File(selectedPath).isFile && !state.isLoadingModel,
                        colors = ButtonDefaults.buttonColors(containerColor = AccentGreen, contentColor = BgRoot),
                        modifier = Modifier.weight(1f),
                    ) {
                        Text("Preload Model", fontWeight = FontWeight.Bold)
                    }
                    OutlinedButton(
                        onClick = { vm.unloadModel() },
                        border = BorderStroke(1.dp, AccentAmber),
                    ) {
                        Text("Unload RAM", color = AccentAmber)
                    }
                }
            }
        }

        // Real-Time Terminal Log Panel
        Card(
            colors = CardDefaults.cardColors(containerColor = BgCard),
            border = BorderStroke(1.dp, BorderGlass),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("REAL-TIME TERMINAL LOG", color = BorderAccent, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    OutlinedButton(onClick = { vm.clearLogs() }, border = BorderStroke(1.dp, BorderGlass)) {
                        Text("Clear", color = TextSecondary, fontSize = 11.sp)
                    }
                }
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(180.dp)
                        .background(BgInput, RoundedCornerShape(8.dp))
                        .padding(8.dp)
                        .verticalScroll(rememberScrollState())
                ) {
                    Text(
                        text = if (state.logs.isEmpty()) "(No logs yet)" else state.logs.joinToString("\n"),
                        color = TextSecondary,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp,
                    )
                }
            }
        }
    }
}
