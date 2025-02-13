rule VirTool_Win64_Wapinz_A_2147846430_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Wapinz.A!MTB"
        threat_id = "2147846430"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Wapinz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b 65 a8 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? e8 f8 ?? ?? ?? 8b 55 a8 48 8d ?? ?? ?? ?? ?? e8 e9 ?? ?? ?? 48 8d ?? ?? ?? 48 8b ce ff 15 ?? ?? ?? ?? 85 c0 74 56 48 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b d3 48 8d ?? ?? ?? ?? ?? e8 98 ?? ?? ?? 48 8d ?? ?? ?? ?? ?? e8 8c ?? ?? ?? 48 ?? ?? ?? 48 89 44 24 20 41 b9 20 00 00 00 41 b8 b2 01 00 00 48 8b d3 48 8b 0f ff 15 ?? ?? ?? ?? 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 05 ca 4d 00 00 48 33 c4 48 89 85 f8 01 00 00 4c 8b e9 49 8b d0 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 0f 85}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 89 74 24 20 41 b9 b2 01 00 00 4d 8b c5 48 8b 54 24 50 48 8b ce ff 15 ?? ?? ?? ?? 85 c0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

