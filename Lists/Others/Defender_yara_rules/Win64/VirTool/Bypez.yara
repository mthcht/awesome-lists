rule VirTool_Win64_Bypez_A_2147838152_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bypez.A!MTB"
        threat_id = "2147838152"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bypez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 04 ff c0 89 45 04 48 63 45 04 48 b9 e0 1a 2c 94 fb 7f 00 00 48 03 c1 48 c7 44 24 20 00 00 00 00 41 b9 01 00 00 00 4c 8b 85 18 01 00 00 48 8b d0 48 8b 4d 48 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 04 00 00 00 00 c7 45 24 00 00 00 00 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 24 44 8b 45 24 33 d2 b9 ff ff 1f 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 04 00 00 00 00 33 d2 b9 02 00 00 00 e8 ?? ?? ?? ?? 48 89 45 28 48 83 7d 28 ff 74 ?? c7 45 50 30 01 00 00 48 8d ?? ?? 48 8b 4d 28 e8 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

