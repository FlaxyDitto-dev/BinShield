package com.flaxyditto.ghidraguard

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.flaxyditto.ghidraguard.ui.screens.NetworkScreen
import com.flaxyditto.ghidraguard.ui.screens.PatchLabScreen
import com.flaxyditto.ghidraguard.ui.screens.ScannerScreen
import com.flaxyditto.ghidraguard.ui.screens.SettingsScreen
import com.flaxyditto.ghidraguard.ui.screens.VaultScreen
import com.flaxyditto.ghidraguard.ui.theme.BgCardAlt
import com.flaxyditto.ghidraguard.ui.theme.BgRoot
import com.flaxyditto.ghidraguard.ui.theme.BgSidebar
import com.flaxyditto.ghidraguard.ui.theme.BorderAccent
import com.flaxyditto.ghidraguard.ui.theme.GhidraGuardTheme
import com.flaxyditto.ghidraguard.ui.theme.TextMuted
import com.flaxyditto.ghidraguard.ui.theme.TextPrimary
import com.flaxyditto.ghidraguard.viewmodel.GhidraGuardViewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            GhidraGuardTheme {
                GhidraGuardAppRoot()
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GhidraGuardAppRoot(vm: GhidraGuardViewModel = viewModel()) {
    val state by vm.uiState.collectAsState()

    val tabs = listOf(
        Triple("Scanner", Icons.Default.Security, 0),
        Triple("AI Lab", Icons.Default.Build, 1),
        Triple("Network", Icons.Default.Wifi, 2),
        Triple("Vault", Icons.Default.Lock, 3),
        Triple("Engines", Icons.Default.Settings, 4),
    )

    Scaffold(
        containerColor = BgRoot,
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = BgSidebar,
                    titleContentColor = BorderAccent,
                ),
                title = {
                    Column {
                        Text(
                            text = "GHIDRAGUARD ANDROID",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            color = BorderAccent,
                        )
                        Text(
                            text = "v0.2.0 • 100% Offline Direct On-Device AI & ELF RE",
                            fontSize = 11.sp,
                            color = TextMuted,
                        )
                    }
                },
            )
        },
        bottomBar = {
            NavigationBar(containerColor = BgSidebar) {
                tabs.forEach { (label, icon, idx) ->
                    NavigationBarItem(
                        selected = state.selectedTab == idx,
                        onClick = { vm.selectTab(idx) },
                        icon = { Icon(icon, contentDescription = label) },
                        label = { Text(label, fontSize = 11.sp) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = BorderAccent,
                            selectedTextColor = BorderAccent,
                            unselectedIconColor = TextMuted,
                            unselectedTextColor = TextMuted,
                            indicatorColor = BgCardAlt,
                        ),
                    )
                }
            }
        },
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(BgRoot)
                .padding(innerPadding)
                .fillMaxWidth()
        ) {
            when (state.selectedTab) {
                0 -> ScannerScreen(state = state, vm = vm)
                1 -> PatchLabScreen(state = state, vm = vm)
                2 -> NetworkScreen(state = state, vm = vm)
                3 -> VaultScreen(state = state, vm = vm)
                else -> SettingsScreen(state = state, vm = vm)
            }
        }
    }
}
