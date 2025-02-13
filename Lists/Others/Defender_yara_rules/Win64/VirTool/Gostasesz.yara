rule VirTool_Win64_Gostasesz_A_2147913709_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Gostasesz.A!MTB"
        threat_id = "2147913709"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Gostasesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 7d 18 00 ?? ?? ?? ?? ?? ?? 48 c7 45 d0 00 00 00 00 ?? ?? ?? ?? 48 8b 45 18 49 89 d0 48 c7 c2 02 00 00 80 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 45 dc 83 7d dc 00 ?? ?? 48 8b 45 d0 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b 45 e0 48 8b 4d f0 48 8b 45 f8 8b 55 dc 89 54 24 20 4d 89 c1 49 89 c8 48 89 c2 [0-18] b8 01 00 00 00 ?? ?? ?? ?? ?? 8b 45 ec 0b 45 20 41 89 c0 48 8b 45 d0 48 8b 55 28 48 8b 4d 10 48 89 4c 24 20 45 89 c1 41 b8 00 00 00 00 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 45 d0 48 8b 55 18 ?? ?? ?? ?? 48 89 4c 24 40 ?? ?? ?? ?? 48 89 4c 24 38 48 c7 44 24 30 00 00 00 00 c7 44 24 28 3f 00 0f 00 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 41 b8 00 00 00 00 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 45 d8 48 8b 45 d0 48 3d 02 00 00 80}  //weight: 1, accuracy: Low
        $x_1_4 = {49 89 d1 49 89 c0 ba 01 00 00 00 [0-40] 48 8b 85 b8 0b 00 00 48 89 c2 48 8b 8d e0 0b 00 00 ?? ?? ?? ?? ?? 89 85 f4 0a 00 00 83 bd f4 0a 00 00 00 ?? ?? ?? ?? ?? ?? 48 8b 85 38 0b 00 00 48 89 c2 48 8b 8d e0 0b 00 00 ?? ?? ?? ?? ?? 89 85 f4 0a 00 00 83 bd f4 0a 00 00 00 ?? ?? ?? ?? ?? ?? 48 8b 85 b0 0b 00 00 48 89 c2 48 8b 8d e0 0b 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {48 8b 85 b8 01 00 00 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 85 08 03 00 00 48 89 c2 48 8b 8d 00 03 00 00 ?? ?? ?? ?? ?? 48 89 85 d0 02 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c2 48 8b 8d 00 03 00 00 ?? ?? ?? ?? ?? 89 85 cc 02 00 00 48 83 bd d0 02 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

