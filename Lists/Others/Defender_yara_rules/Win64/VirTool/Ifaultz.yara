rule VirTool_Win64_Ifaultz_A_2147835314_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Ifaultz.A!MTB"
        threat_id = "2147835314"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Ifaultz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 5c 04 00 00 00 48 8b 8d d0 01 00 00 ff 15 ?? ?? ?? ?? 48 89 85 98 00 00 00 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 89 85 b8 00 00 00 4c 8d ?? ?? 4c 8d ?? ?? ?? ?? ?? 48 8d ?? ?? 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 85 d4 00 00 00 83 bd d4 00 00 00 00 7c ?? 48 8b 45 28 48 8b 00 4c 8b 85 98 00 00 00 48 8b 95 b8 00 00 00 48 8b 4d 28}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 44 24 20 00 00 00 00 41 b9 30 00 00 00 4c 8d ?? ?? 33 d2 48 8b 8d d8 00 00 00 ff 15 ?? ?? ?? ?? 48 c7 44 24 20 00 00 00 00 41 b9 08 00 00 00 4c 8d ?? ?? 48 8d ?? ?? 48 8b 8d d8 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 45 78 48 8b 40 20 48 83 c0 60 48 8b 95 28 03 00 00 48 8b c8 ff 15 ?? ?? ?? ?? 48 8b 45 78 48 8b 40 20 48 83 c0 70 48 8b 95 28 03 00 00 48 8b c8 ff 15 ?? ?? ?? ?? 41 b8 04 01 00 00 48 8d 95 80 05 00 00 33 c9 ff 15 ?? ?? ?? ?? 48 8b 45 78 48 8b 40 18 48 8b 40 10 48 89 85 a8 07 00 00 48 8b 85 98 00 00 00 48 8b 40 10 48 89 85 c8 07 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

