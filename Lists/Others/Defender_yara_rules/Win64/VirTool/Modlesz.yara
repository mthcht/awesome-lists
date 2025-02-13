rule VirTool_Win64_Modlesz_A_2147847060_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Modlesz.A!MTB"
        threat_id = "2147847060"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Modlesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b d8 ff 15 ?? ?? ?? ?? 48 63 4b 3c 8b 5c 19 28 48 8d 0d ?? ?? ?? ?? 8b d3 e8 47 ?? ?? ?? 48 03 de 48 8d ?? ?? ?? ?? ?? 48}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b9 00 30 00 00 c7 44 24 20 04 00 00 00 48 63 f0 33 d2 4c 8b c6 48 8b cf ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b c8 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 89 74 24 58 48 8d 0d ?? ?? ?? ?? e8 95 ?? ?? ?? 45 33 f6 4c 8d 05 ?? ?? ?? ?? 4c 8b ce 4c 89 74 24 20 48 8b d3 48 8b cf ff 15 ?? ?? ?? ?? 85 c0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

