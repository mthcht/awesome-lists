rule VirTool_Win64_ObfuscateShell_B_2147758795_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/ObfuscateShell.B!MTB"
        threat_id = "2147758795"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ObfuscateShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 dc 8b 45 e0 c1 e0 02 89 45 d8 8b 45 dc c1 f8 04 09 45 d8 48 8b 45 18 48 ?? ?? ?? 48 89 55 18 8b 55 d8 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 d0 8b 45 d4 c1 e0 06 25 ff 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 c1 e8 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 89 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

