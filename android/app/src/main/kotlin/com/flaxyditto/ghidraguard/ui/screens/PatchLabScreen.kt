package com.flaxyditto.ghidraguard.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.flaxyditto.ghidraguard.ui.theme.AccentCyan
import com.flaxyditto.ghidraguard.ui.theme.AccentGreen
import com.flaxyditto.ghidraguard.ui.theme.AccentPurple
import com.flaxyditto.ghidraguard.ui.theme.BgCard
import com.flaxyditto.ghidraguard.ui.theme.BgCardAlt
import com.flaxyditto.ghidraguard.ui.theme.BgInput
import com.flaxyditto.ghidraguard.ui.theme.BorderAccent
import com.flaxyditto.ghidraguard.ui.theme.BorderGlass
import com.flaxyditto.ghidraguard.ui.theme.TextMuted
import com.flaxyditto.ghidraguard.ui.theme.TextPrimary
import com.flaxyditto.ghidraguard.ui.theme.TextSecondary
import com.flaxyditto.ghidraguard.viewmodel.GhidraGuardUiState
import com.flaxyditto.ghidraguard.viewmodel.GhidraGuardViewModel

@Composable
fun PatchLabScreen(
    state: GhidraGuardUiState,
    vm: GhidraGuardViewModel,
) {
    val target = state.activeTarget
    val scroll = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scroll)
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        // Header & Launch Card
        Card(
            colors = CardDefaults.cardColors(containerColor = BgCard),
            border = BorderStroke(1.dp, BorderGlass),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "AI Decompile Audit & Surgical ELF Patch Lab",
                    color = TextPrimary,
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = if (target != null) {
                        "Target: ${target.appName} (${target.packageName})"
                    } else {
                        "No target selected — choose an app or APK from the Scanner tab."
                    },
                    color = BorderAccent,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                )
                val modelLabel = java.io.File(state.aiConfig.modelPath).name.ifBlank { "Built-In On-Device Analyzer" }
                Text(
                    text = "Engine: Direct On-Device ($modelLabel • ${if (state.aiConfig.useGpu) "Mobile GPU" else "CPU"} • Zero Ollama)",
                    color = TextSecondary,
                    fontSize = 11.sp,
                )
                Text(
                    text = "Status: ${state.auditStatus}",
                    color = AccentGreen,
                    fontWeight = FontWeight.Bold,
                    fontSize = 12.sp,
                )

                Button(
                    onClick = { vm.runAiAuditAndPatch() },
                    enabled = target != null && !state.isAuditing,
                    colors = ButtonDefaults.buttonColors(containerColor = AccentPurple, contentColor = TextPrimary),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        if (state.isAuditing) "Running Iterative AI Audit..." else "Start Iterative AI Audit & Patch",
                        fontWeight = FontWeight.Bold,
                    )
                }
            }
        }

        // Extracted Static Metadata Preview
        if (target != null) {
            Card(
                colors = CardDefaults.cardColors(containerColor = BgCard),
                border = BorderStroke(1.dp, BorderGlass),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Extracted APK / DEX / Native ELF Artifacts", color = BorderAccent, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                    Text(
                        text = buildString {
                            appendLine("SHA-256: ${target.sha256.take(32)}...")
                            appendLine("DEX Files: ${target.dexCount} | Native ELF Libs: ${target.nativeLibs.size} | Max Entropy: ${target.maxEntropy}")
                            if (target.dangerousPermissions.isNotEmpty()) {
                                appendLine("Permissions: ${target.dangerousPermissions.joinToString { it.substringAfterLast('.') }}")
                            }
                            if (target.nativeLibs.isNotEmpty()) {
                                appendLine("Native Libs:")
                                target.nativeLibs.take(5).forEach { lib ->
                                    appendLine("  • ${lib.entryPath} [${lib.arch}] (${lib.executableSections.size} exec sec)")
                                }
                            }
                            if (target.suspiciousStrings.isNotEmpty()) {
                                appendLine("Top Suspicious Strings:")
                                target.suspiciousStrings.take(6).forEach { s ->
                                    appendLine("  • $s")
                                }
                            }
                        },
                        color = TextSecondary,
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

        // Pass-by-Pass AI Audit Reports
        if (state.auditReports.isNotEmpty()) {
            Card(
                colors = CardDefaults.cardColors(containerColor = BgCard),
                border = BorderStroke(1.dp, BorderGlass),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Pass-by-Pass Local AI Audit Reports", color = AccentCyan, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    state.auditReports.forEach { rep ->
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(BgCardAlt, RoundedCornerShape(10.dp))
                                .padding(10.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                                Text("Pass ${rep.passNumber} — ${rep.riskVerdict}", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                                Text(if (rep.isClean) "CLEAN" else "ACTION NEEDED", color = if (rep.isClean) AccentGreen else BorderAccent, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            }
                            Text(rep.summary, color = TextSecondary, fontSize = 12.sp)
                            if (rep.findings.isNotEmpty()) {
                                Text(
                                    text = rep.findings.joinToString("\n") { "• $it" },
                                    color = TextMuted,
                                    fontSize = 11.sp,
                                )
                            }
                            if (rep.recommendedActions.isNotEmpty()) {
                                Text(
                                    text = "Actions:\n" + rep.recommendedActions.joinToString("\n") { "→ $it" },
                                    color = AccentGreen,
                                    fontSize = 11.sp,
                                )
                            }
                        }
                    }
                }
            }
        }

        // Byte-Level ELF Patch Diff Summary
        Card(
            colors = CardDefaults.cardColors(containerColor = BgCard),
            border = BorderStroke(1.dp, BorderGlass),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Surgical ELF .text Patch Diff Summary", color = AccentGreen, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                if (state.appliedPatches.isEmpty()) {
                    Text("No native ELF byte patches applied yet.", color = TextMuted, fontSize = 12.sp)
                } else {
                    state.appliedPatches.forEachIndexed { idx, p ->
                        Text(
                            text = "#${idx + 1} [Pass ${p.passNumber}] ${p.targetEntry} (${p.arch})\n" +
                                "  Func: ${p.functionName} @ ${p.fileOffsetHex} (${p.strategy})\n" +
                                "  BEFORE: ${p.beforeHex}\n" +
                                "  AFTER : ${p.afterHex}",
                            color = AccentGreen,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(BgInput, RoundedCornerShape(8.dp))
                                .padding(8.dp),
                        )
                    }
                    if (state.sanitizedApkPath.isNotBlank()) {
                        Text(
                            text = "Sanitized APK saved (signatures stripped): ${state.sanitizedApkPath}",
                            color = BorderAccent,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                        )
                    }
                }
            }
        }
    }
}
