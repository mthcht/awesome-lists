rule VirTool_Win64_DownRefDllz_A_2147839551_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/DownRefDllz.A!MTB"
        threat_id = "2147839551"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "DownRefDllz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 85 a4 02 00 00 ff 00 00 00 48 8d ?? ?? ?? ?? ?? 48 89 44 24 30 48 8d ?? ?? ?? ?? ?? 48 89 44 24 28 48 c7 44 24 20 00 00 00 00 41 b9 02 00 00 00 4c 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 c7 c1 02 00 00 80 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {44 8b 45 24 48 8b 55 68 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 8b f9 48 8b f0 b9 10 00 00 00 f3 a4}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 20 00 00 00 00 45 33 c9 45 33 c0 33 d2 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 89 85 f8 00 00 00 48 83 bd f8 00 00 00 00 74 28}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 44 24 30 00 00 00 00 48 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 45 33 c9 4c 8b 85 a8 04 00 00 48 8d ?? ?? ?? ?? ?? 48 8b 8d 18 01 00 00 ff 15 ?? ?? ?? ?? 48 89 85 38 01 00 00 eb 14}  //weight: 1, accuracy: Low
        $x_1_5 = {44 8b 45 74 48 8b 95 b8 00 00 00 48 8b 8d 38 01 00 00 ff 15 ?? ?? ?? ?? 85 c0 75 19}  //weight: 1, accuracy: Low
        $x_1_6 = {48 63 85 04 06 00 00 48 8b 8d 78 05 00 00 0f b7 04 41 48 8b 8d 58 05 00 00 8b 04 81 48 8b 8d 98 03 00 00 48 03 c8 48 8b c1 48 89 85 b8 05 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

