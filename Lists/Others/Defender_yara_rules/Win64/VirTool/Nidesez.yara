rule VirTool_Win64_Nidesez_A_2147853079_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Nidesez.A!MTB"
        threat_id = "2147853079"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Nidesez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b 4d 94 48 ?? ?? ?? 4c ?? ?? ?? 48 89 44 24 20 48 8d ?? ?? ?? 48 c7 c1 ff ff ff ff ff 15 ?? ?? ?? ?? 85 c0 78 18 48 8d ?? ?? ?? ?? ?? e8 0d ?? ?? ?? 48 8d ?? ?? ?? ?? ?? e8 01}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 28 04 00 00 00 4c ?? ?? ?? 45 33 c0 89 75 94 66 48 0f 7e c9 0f 29 4c 24 50 48 8d ?? ?? ?? 48 89 74 24 70 48 c7 45 98 01 00 00 00 c7 44 24 20 00 10 00 00 ff 15 ?? ?? ?? ?? 85 c0 78}  //weight: 1, accuracy: Low
        $x_1_3 = {48 c7 45 98 01 00 00 00 e8 33 ?? ?? ?? 48 8b d0 48 89 44 24 70 48 8d ?? ?? ?? ?? ?? e8 bf ?? ?? ?? 48 8b 5c 24 70 48 ?? ?? ?? 41 b9}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 8b 44 24 30 44 8b cb 48 8b 15 d9 40 00 00 48 8b cf 4c 89 6c 24 20 ff 15 ?? ?? ?? ?? 85 c0 75 0c 48 8d}  //weight: 1, accuracy: Low
        $x_1_5 = {48 8b c2 89 4d 04 48 8d ?? ?? ?? ?? ?? 48 89 4d 88 0f 11 45 a4 48 8b 08 0f 11 45 b4 0f 11 45 c4 0f 11 45 d4 0f 11 45 e4 0f 11 45 f4 0f 11 44 24 78 ff 15 ?? ?? ?? ?? 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

