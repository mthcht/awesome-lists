rule VirTool_Win64_GatWalkz_A_2147839549_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/GatWalkz.A!MTB"
        threat_id = "2147839549"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "GatWalkz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 b8 9b b8 a6 80 34 37 bd f5 48 89 45 10 48 b8 41 07 6f 48 ba c2 a3 68 48 89 45 28 48 b8 37 6a fb 46 10 cb 8b 85 48 89 45 40 48 b8 5f 01 c5 88 b2 7d dc 64 48 89 45 58 48 b8 cb 1b 55 4e 17 fa a2 c6 48 89 45 70 48 8d ?? ?? e8 ?? ?? ?? ?? 85 c0 74 14 48 8d ?? ?? e8 ?? ?? ?? ?? 85 c0 75 07}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f8 4c 75 64 b8 01 00 00 00 48 6b c0 01 48 8b 8d c8 00 00 00 0f b6 04 01 3d 8b 00 00 00 75 49 b8 01 00 00 00 48 6b c0 02 48 8b 8d c8 00 00 00 0f b6 04 01 3d d1 00 00 00 75 2e b8 01 00 00 00 48 6b c0 03 48 8b 8d c8 00 00 00 0f b6 04 01 3d b8 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {48 8b 45 40 48 8b 4d 10 48 2b c8 48 8b c1 48 89 45 68 b8 ff ff 00 00 66 89 85 84 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {0f b7 85 24 01 00 00 48 8b 8d 08 01 00 00 0f b7 04 41 48 8b 8d c8 00 00 00 8b 04 81 48 8b 4d 48 48 03 41 30 48 89 85 68 01 00 00 48 8b 8d 48 01 00 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

