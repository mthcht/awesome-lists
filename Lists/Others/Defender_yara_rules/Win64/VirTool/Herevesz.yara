rule VirTool_Win64_Herevesz_A_2147922942_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Herevesz.A!MTB"
        threat_id = "2147922942"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Herevesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b f8 33 c0 b9 31 00 00 00 f3 aa [0-17] ba 08 00 00 00 48 8b c8 ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 20 41 b9 04 00 00 00 ?? ?? ?? ?? ?? ba 14 00 00 00 48 8b 4c 24 50 ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 02 00 00 00 66 89 44 24 50 0f b7 8c 24 60 02 00 00 ?? ?? ?? ?? ?? ?? 66 89 44 24 52 ?? ?? ?? ?? ?? 48 8b 94 24 58 02 00 00 b9 02 00 00 00 ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 8b 4c 24 28 [0-25] 48 8b 8c 24 50 02 00 00 ?? ?? ?? ?? ?? 8b 44 24 20 83 c8 01 89 44 24 20 48 8b 8c 24 70 02 00 00 ?? ?? ?? ?? ?? 48 8b 84 24 50 02 00 00 ?? ?? ?? ?? ?? 41 b8 10 00 00 00 ?? ?? ?? ?? ?? 48 8b 4c 24 28}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 84 24 cc 00 00 00 99 81 e2 ff ff 00 00 03 c2 25 ff ff 00 00 2b c2 b9 00 00 01 00 2b c8 8b c1 89 44 24 54 8b 84 24 e4 00 00 00 8b 4c 24 54 03 c8 8b c1 2b 44 24 50 8b c0 41 b9 04 00 00 00 41 b8 00 10 00 00 8b d0 33 c9 ?? ?? ?? ?? ?? ?? ?? 48 63 4c 24 54 48 03 c1 8b 4c 24 50 48 2b c1 48 89 44 24 38 c7 44 24 2c 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {33 c0 83 f8 01 [0-17] f2 0f 2a c0 f2 0f 5e 05 b4 35 05 00 f2 0f 59 44 24 48 f2 0f 59 05 96 35 05 00 f2 0f 5c 44 24 48 f2 0f 11 84 24 b0 00 00 00 f2 0f 10 84 24 a8 00 00 00 f2 0f 58 84 24 b0 00 00 00 f2 0f 59 05 75 35 05 00 f2 48 0f 2c c0 8b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

