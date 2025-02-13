rule VirTool_Win32_ObfuscateShell_A_2147758794_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/ObfuscateShell.A!MTB"
        threat_id = "2147758794"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ObfuscateShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 e0 8b 45 ?? c1 e0 02 89 45 ?? 8b 45 ?? c1 f8 04 09 45 ?? 8b 45 ?? 8d ?? ?? 89 55 ?? 8b 55 ?? 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 d4 8b 45 d8 c1 e0 06 25 ff 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {89 44 24 04 8d ?? ?? ?? ?? ?? ?? 89 04 24 e8 ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ?? 89 04 24 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

