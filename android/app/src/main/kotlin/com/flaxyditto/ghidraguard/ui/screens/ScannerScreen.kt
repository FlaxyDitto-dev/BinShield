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
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.flaxyditto.ghidraguard.engine.ApkThreatFinding
import com.flaxyditto.ghidraguard.ui.theme.AccentAmber
import com.flaxyditto.ghidraguard.ui.theme.AccentCyan
import com.flaxyditto.ghidraguard.ui.theme.AccentGreen
import com.flaxyditto.ghidraguard.ui.theme.AccentPurple
import com.flaxyditto.ghidraguard.ui.theme.BgCard
import com.flaxyditto.ghidraguard.ui.theme.BgCardAlt
import com.flaxyditto.ghidraguard.ui.theme.BgRoot
import com.flaxyditto.ghidraguard.ui.theme.BorderAccent
import com.flaxyditto.ghidraguard.ui.theme.BorderGlass
import com.flaxyditto.ghidraguard.ui.theme.TextMuted
import com.flaxyditto.ghidraguard.ui.theme.TextPrimary
import com.flaxyditto.ghidraguard.ui.theme.TextSecondary
import com.flaxyditto.ghidraguard.ui.theme.severityColor
import com.flaxyditto.ghidraguard.viewmodel.OpcodeShieldUiState
import com.flaxyditto.ghidraguard.viewmodel.GhidraGuardViewModel

@Composable
fun ScannerScreen(
    state: OpcodeShieldUiState,
    vm: GhidraGuardViewModel,
) {
    val context = LocalContext.current
    val apkPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            var name = "selected.apk"
            context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (idx >= 0 && cursor.moveToFirst()) {
                    name = cursor.getString(idx) ?: name
                }
            }
            vm.inspectPickedApk(uri, name)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        // Controls Card
        Card(
            colors = CardDefaults.cardColors(containerColor = BgCard),
            border = BorderStroke(1.dp, BorderGlass),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "Android App, APK, ELF & Windows PE (.exe/.dll) Scanner",
                    color = TextPrimary,
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = state.scanStatus,
                    color = TextSecondary,
                    fontSize = 12.sp,
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Button(
                        onClick = { vm.runInstalledAppScan() },
                        enabled = !state.isScanning,
                        colors = ButtonDefaults.buttonColors(containerColor = AccentCyan, contentColor = BgRoot),
                        modifier = Modifier.weight(1f),
                    ) {
                        Text(if (state.isScanning) "Scanning..." else "Scan Installed Apps", fontWeight = FontWeight.Bold)
                    }
                    OutlinedButton(
                        onClick = { apkPicker.launch(arrayOf("*/*")) },
                        border = BorderStroke(1.dp, BorderAccent),
                    ) {
                        Text("Inspect APK / EXE", color = BorderAccent)
                    }
                }

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Checkbox(
                        checked = state.includeSystemApps,
                        onCheckedChange = { vm.setIncludeSystemApps(it) },
                        colors = CheckboxDefaults.colors(checkedColor = AccentCyan),
                    )
                    Text("Include System Apps", color = TextSecondary, fontSize = 12.sp)
                    Spacer(Modifier.width(12.dp))
                    Text("Min Risk: ${state.minRiskScore}", color = BorderAccent, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                }

                Slider(
                    value = state.minRiskScore.toFloat(),
                    onValueChange = { vm.setMinRiskScore(it.toInt()) },
                    valueRange = 0f..70f,
                    colors = SliderDefaults.colors(thumbColor = BorderAccent, activeTrackColor = AccentCyan),
                )

                if (state.isScanning || state.scanProgress > 0f) {
                    LinearProgressIndicator(
                        progress = { state.scanProgress },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(6.dp),
                        color = BorderAccent,
                        trackColor = BgCardAlt,
                    )
                }
            }
        }

        // Findings List
        if (state.findings.isEmpty()) {
            Card(
                colors = CardDefaults.cardColors(containerColor = BgCard),
                border = BorderStroke(1.dp, BorderGlass),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
            ) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(
                        text = if (state.scanProgress >= 1f) {
                            "Clean! No apps met the risk threshold."
                        } else {
                            "Tap 'Scan Installed Apps' or 'Inspect APK' to start local heuristic analysis."
                        },
                        color = if (state.scanProgress >= 1f) AccentGreen else TextMuted,
                        fontSize = 13.sp,
                        modifier = Modifier.padding(24.dp),
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(state.findings, key = { it.id }) { finding ->
                    FindingCard(
                        finding = finding,
                        onAudit = { vm.openInPatchLab(finding) },
                        onQuarantine = { vm.quarantineFinding(finding) },
                    )
                }
            }
        }
    }
}

@Composable
private fun FindingCard(
    finding: ApkThreatFinding,
    onAudit: () -> Unit,
    onQuarantine: () -> Unit,
) {
    val sevColor = severityColor(finding.severity)
    Card(
        colors = CardDefaults.cardColors(containerColor = BgCardAlt),
        border = BorderStroke(1.dp, BorderGlass),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Box(
                    modifier = Modifier
                        .background(sevColor, RoundedCornerShape(6.dp))
                        .padding(horizontal = 8.dp, vertical = 3.dp)
                ) {
                    Text(
                        text = "${finding.severity} (${finding.riskScore})",
                        color = BgRoot,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                    )
                }
                Text(
                    text = finding.appName,
                    color = TextPrimary,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f),
                )
            }

            Text(
                text = "${finding.packageName} • ${finding.source} • Entropy ${finding.maxEntropy} • ${finding.nativeLibs.size} ELF lib(s)",
                color = TextSecondary,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
            )

            if (finding.indicators.isNotEmpty()) {
                Text(
                    text = finding.indicators.take(3).joinToString(" | "),
                    color = TextMuted,
                    fontSize = 11.sp,
                )
            }

            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Button(
                    onClick = onAudit,
                    colors = ButtonDefaults.buttonColors(containerColor = AccentPurple, contentColor = TextPrimary),
                    modifier = Modifier.weight(1f),
                ) {
                    Text("AI Audit & ELF Patch", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                }
                OutlinedButton(
                    onClick = onQuarantine,
                    border = BorderStroke(1.dp, AccentAmber),
                ) {
                    Text("Vault Copy", color = AccentAmber, fontSize = 12.sp)
                }
            }
        }
    }
}
