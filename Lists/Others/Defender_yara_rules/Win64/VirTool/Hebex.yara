rule VirTool_Win64_Hebex_A_2147917413_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Hebex.A!MTB"
        threat_id = "2147917413"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Hebex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 0d 47 1b 00 00 ?? ?? ?? ?? ?? 48 8b c8 [0-19] c7 45 c8 2c 59 ec 8c c7 45 cc a1 07 d9 11 c7 45 d0 b1 5e 00 0d c7 45 d4 56 bf e6 ee 48 c7 45 b8 3c 03 00 00 c7 45 c0 c0 00 00 00 c7 45 c4 00 00 00 46 0f 10 05 71 22 00 00 0f 11 45 d8 ?? ?? ?? ?? 48 89 44 24 20 ?? ?? ?? ?? 33 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 0d c4 1a 00 00 ?? ?? ?? ?? ?? 48 8b c8 [0-19] 8b cb 81 e1 00 00 ff ff 81 f9 00 00 07 80 0f b7 c3 ?? ?? ?? ?? ?? ?? b8 eb 03 00 00 ?? ?? ?? ?? ?? 48 8b 4d a0 48 8b 01 [0-19] 8b d8 85 c0 [0-17] 48 8b 01 41 b9 01 00 00 00 45 33 c0 8b d6}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 7d 10 [0-18] 48 8b c8 49 8b d6 ?? ?? ?? ?? ?? 48 8b c8 [0-19] 48 8b 07 49 8b d6 48 8b cf ?? ?? ?? 8b d8 85 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 54 24 30 c7 44 24 28 01 00 00 00 4c 89 6c 24 20 41 b9 17 00 00 00 45 33 c0 ?? ?? ?? ?? ?? ?? ?? 8b d8 ?? ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

