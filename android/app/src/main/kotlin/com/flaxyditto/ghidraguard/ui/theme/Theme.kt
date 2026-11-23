package com.flaxyditto.ghidraguard.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// Exact BinShield Dark Glassmorphic Palette (matching desktop CustomTkinter app)
val BgRoot = Color(0xFF090D16)
val BgSidebar = Color(0xFF0E1422)
val BgCard = Color(0xFF121A2B)
val BgCardAlt = Color(0xFF162033)
val BgInput = Color(0xFF0C1220)
val BorderGlass = Color(0xFF22314D)
val BorderAccent = Color(0xFF38BDF8)
val AccentCyan = Color(0xFF0EA5E9)
val AccentPurple = Color(0xFF8B5CF6)
val AccentGreen = Color(0xFF10B981)
val AccentRed = Color(0xFFEF4444)
val AccentAmber = Color(0xFFF59E0B)
val TextPrimary = Color(0xFFF1F5F9)
val TextSecondary = Color(0xFF94A3B8)
val TextMuted = Color(0xFF64748B)

fun severityColor(severity: String): Color = when (severity.uppercase()) {
    "CRITICAL" -> AccentRed
    "HIGH" -> Color(0xFFF97316)
    "MEDIUM" -> Color(0xFFEAB308)
    else -> Color(0xFF22C55E)
}

private val BinShieldDarkColors = darkColorScheme(
    primary = AccentCyan,
    onPrimary = BgRoot,
    secondary = AccentPurple,
    onSecondary = TextPrimary,
    tertiary = AccentGreen,
    background = BgRoot,
    onBackground = TextPrimary,
    surface = BgCard,
    onSurface = TextPrimary,
    surfaceVariant = BgCardAlt,
    onSurfaceVariant = TextSecondary,
    outline = BorderGlass,
    error = AccentRed,
)

private val BinShieldTypography = Typography(
    headlineSmall = TextStyle(
        fontWeight = FontWeight.Bold,
        fontSize = 20.sp,
        color = TextPrimary,
    ),
    titleMedium = TextStyle(
        fontWeight = FontWeight.Bold,
        fontSize = 15.sp,
        color = TextPrimary,
    ),
    bodyMedium = TextStyle(
        fontSize = 13.sp,
        color = TextSecondary,
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontSize = 11.sp,
        color = TextMuted,
    ),
)

@Composable
fun GhidraGuardTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = BinShieldDarkColors,
        typography = BinShieldTypography,
        content = content,
    )
}
