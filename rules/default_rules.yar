/*
 * GhidraGuard v2.0.0 Default Offline YARA Ruleset
 * Drop additional .yar / .yara files into this rules/ folder for automatic loading.
 */

rule GG_x64_PEB_Walk_Shellcode {
    meta:
        description = "x64 PEB walk shellcode (mov rax/rcx, gs:[0x60])"
        severity = "CRITICAL"
        category = "Shellcode Injection"
    strings:
        $peb_rax = { 65 48 8B 04 25 60 00 00 00 }
        $peb_rcx = { 65 48 8B 0C 25 60 00 00 00 }
        $x86_peb = { 64 A1 30 00 00 00 }
    condition:
        any of them
}

rule GG_Shellcode_Prologue_GetPC {
    meta:
        description = "x64 shellcode stack-alignment prologue or GetPC call/pop stub"
        severity = "HIGH"
        category = "Shellcode Injection"
    strings:
        $prolog = { FC 48 83 E4 F0 }
        $getpc1 = { E8 00 00 00 00 58 }
        $getpc2 = { E8 00 00 00 00 5B }
    condition:
        any of them
}

rule GG_Webhook_Exfiltration {
    meta:
        description = "Discord or Telegram Bot API exfiltration endpoint"
        severity = "CRITICAL"
        category = "C2 / Exfiltration"
    strings:
        $discord = "discord.com/api/webhooks" nocase
        $telegram = "api.telegram.org/bot" nocase
    condition:
        any of them
}

rule GG_Ransomware_Shadow_Delete {
    meta:
        description = "Ransomware shadow-copy deletion or Defender exclusion tampering"
        severity = "CRITICAL"
        category = "Ransomware / Tampering"
    strings:
        $vss = "vssadmin delete shadows" nocase
        $mp = "Add-MpPreference" nocase
        $bcd = "bcdedit /set" nocase
    condition:
        any of them
}

rule GG_Hidden_PowerShell_Dropper {
    meta:
        description = "Hidden or encoded PowerShell dropper command"
        severity = "HIGH"
        category = "Dropper"
    strings:
        $ps1 = "powershell -nop -w hidden" nocase
        $ps2 = "powershell -enc" nocase
        $iex = "Invoke-Expression" nocase
    condition:
        any of them
}

rule GG_Frida_Xposed_Hook {
    meta:
        description = "Frida gadget/server or Xposed runtime hooking artifact"
        severity = "HIGH"
        category = "Runtime Hooking"
    strings:
        $f1 = "frida-gadget" nocase
        $f2 = "frida-server" nocase
        $xp = "XposedBridge" nocase
    condition:
        any of them
}

rule GG_UPX_Packer {
    meta:
        description = "UPX executable packer signature"
        severity = "MEDIUM"
        category = "Packed / Obfuscated"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx_sig = "UPX!"
    condition:
        2 of them
}
