rule VirTool_Win64_Delunhokesz_A_2147917411_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Delunhokesz.A!MTB"
        threat_id = "2147917411"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Delunhokesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 81 ec c0 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 f0 48 c7 45 ?? 00 00 00 00 48 c7 45 98 00 00 00 00 48 c7 45 a0 00 00 00 00 [0-22] 48 89 45 e8 ?? ?? ?? ?? 48 8b 55 e8 48 8b 45 f0 41 b9 18 00 00 00 49 89 c8 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 45 e0 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 00 c7 44 24 20 03 00 00 00 41 b9 00 00 00 00 41 b8 01 00 00 00 ba 00 00 00 80 [0-22] 48 89 45 d8 48 8b 45 d8 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 41 b8 02 00 00 01 ba 00 00 00 00 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 45 d0 48 8b 45 d0 48 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 41 b8 00 00 00 00 ba 04 00 00 00 48 89 c1 48 8b 05 0b 7d 00 00 ?? ?? 48 89 45 c8 48 8b 45 e0}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 45 b0 48 8b 45 b0 ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? c7 45 8c 00 00 00 00 48 8b 45 b0 8b 40 08 89 c2 48 8b 45 b0 8b 40 0c 89 c1 48 8b 45 e0 48 01 c8 48 89 c1 ?? ?? ?? ?? 49 89 c1 41 b8 40 00 00 00 48 8b 05 66 7c 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {49 89 c8 48 89 c1 ?? ?? ?? ?? ?? 8b 55 8c 48 8b 45 b0 8b 40 08 41 89 c2 48 8b 45 b0 8b 40 0c 89 c1 48 8b 45 e0 48 01 c8 48 89 c1 ?? ?? ?? ?? 49 89 c1 41 89 d0 4c 89 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

