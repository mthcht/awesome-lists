rule VirTool_Win64_Hinteloadesz_A_2147906321_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Hinteloadesz.A!MTB"
        threat_id = "2147906321"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Hinteloadesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 00 30 00 00 48 89 7c 24 50 4c 8b c6 c7 44 24 20 40 00 00 00 33 d2 48 8b cb ?? ?? ?? ?? ?? ?? 48 8b f8 48 85 c0 [0-20] 48 8b c8 [0-16] 4c 89 74 24 58 4c 8b ce 45 33 f6 4c 8b c5 48 8b d7 4c 89 74 24 20 48 8b cb ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 89 74 24 30 4c 8b cf 44 89 74 24 28 45 33 c0 33 d2 4c 89 74 24 20 48 8b cb ?? ?? ?? ?? ?? ?? 48 83 f8 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 13 48 8b c8 ?? ?? ?? ?? ?? 48 8b c8 [0-17] 4c 8b 03 33 d2 48 8b c8 ?? ?? ?? ?? ?? ?? 48 8b d8 4c 8b c0 45 85 e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

