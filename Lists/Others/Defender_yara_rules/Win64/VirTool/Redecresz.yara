rule VirTool_Win64_Redecresz_A_2147890408_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Redecresz.A!MTB"
        threat_id = "2147890408"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Redecresz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 85 8b 00 00 00 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 85 c0 0f 84 a4 00 00 00 48 8d ?? ?? ?? ?? ?? 48 8b c8 ff 15 ?? ?? ?? ?? 48 89 05 b6 c2 00 00 48 85 c0 74 42 48 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 85 40 01 00 00 4c 89 4c 24 58 45 8b e8 4c 8b e2 44 8b f9 4c 8b b5 c0 01 00 00 48 8b b5 c8 01 00 00 48 8b bd d0 01 00 00 48 8b 85 d8 01 00 00 48 89 44 24 50 48 8b 9d e0 01 00 00 48 8d ?? ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {85 d2 75 2b e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8b c8 e8 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 8d 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

