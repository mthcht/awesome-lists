rule VirTool_Win64_Krakesz_A_2147853084_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Krakesz.A!MTB"
        threat_id = "2147853084"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Krakesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 68 e8 ?? ?? ?? ?? 48 8b 0d 02 1c 00 00 45 33 c9 48 89 74 24 40 45 33 c0 48 89 74 24 38 33 d2 48 89 74 24 30 48 89 74 24 28 48 89 74 24 20 48 89 44 24 70 e8 ?? ?? ?? ?? 0f 10 05 30 1f 00 00 48 8b 0d b9 1d 00 00 4c 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 89 38 e8 ?? ?? ?? ?? 44 89 6c 24 58 44 89 6c 24 50 44 89 6c 24 48 4c 89 6c 24 40 4c 89 6c 24 38 4c 89 6c 24 30 4c 89 6c 24 28 4c 89 6c 24 20 48 8b 0d 76 14 00 00 4c 8d}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 85 18 0f 00 00 48 8b 85 b8 0e 00 00 48 c7 85 a0 0e 00 00 ff ff ff ff 48 c7 85 a8 0e 00 00 a0 0f 00 00 4c 89 38 48 ?? ?? ?? 48 89 85 70 13 00 00 48 ?? ?? ?? 48 89}  //weight: 1, accuracy: Low
        $x_1_4 = {8b cf 48 8b 7c 24 60 0f 11 48 30 48 89 4d 38 0f 11 40 40 48 8b 05 86 15 00 00 48 89 85 a8 00 00 00 48 ?? ?? ?? ?? 48 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

