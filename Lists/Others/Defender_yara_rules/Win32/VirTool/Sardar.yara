rule VirTool_Win32_Sardar_A_2147763589_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Sardar.A!MTB"
        threat_id = "2147763589"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Sardar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 6c 24 50 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 84 00 48 8b 05 62 f2 46 00 48 8b 0d 8b ad 2a 00 48 89 04 24 0f 57 c0 0f 11 44 24 08 48 89 4c 24 18 48 8b 44 24 60 48 89 44 24 20 0f 11 44 24 28 e8 ?? ?? ?? ?? 48 8b 44 24 38 48 85 c0 74 1f 48 8b 0d 3d f2 46 00 48 89 0c 24 48 89 44 24 08 e8 ?? ?? ?? ?? 48 8b 6c 24 50 48 83 c4 58 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {65 48 8b 0c 25 28 00 00 00 48 8b 89 00 00 00 00 48 3b 61 10 ?? ?? 48 83 ec 28 48 89 6c 24 20 48 ?? ?? ?? ?? 48 8b 4c 24 40 48 ?? ?? ?? 48 39 c8 ?? ?? 48 8b 44 24 38 0f b6 4c 01 ff 84 c9 75 38 48 8b 0d 09 10 47 00 48 89 0c 24 48 8b 4c 24 30 48 89 4c 24 08 48 89 44 24 10 e8 ?? ?? ?? ?? 48 8b 44 24 18 48 89 44 24 50 48 8b 6c 24 20 48 83 c4 28 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {31 c0 48 8b 8c 24 50 05 00 00 87 81 30 03 00 00 b8 01 00 00 00 f0 0f c1 81 08 03 00 00 48 8b 05 9f e5 46 00 48 89 04 24 48 8b 44 24 48 48 89 44 24 08 e8 74 f9 ff ff 48 8b 05 25 e6 46 00 48 89 04 24 48 8b 44 24 48 48 89 44 24 08 e8 5a f9 ff ff 48 8b ac 24 40 05 00 00 48 81 c4 48 05 00 00 c3}  //weight: 1, accuracy: High
        $x_1_4 = {48 83 ec 30 48 89 6c 24 28 48 8d 6c 24 28 48 8b 44 24 38 48 85 c0 0f 84 a5 00 00 00 65 48 8b 04 25 28 00 00 00 48 8b 80 00 00 00 00 48 8b 40 30 48 89 44 24 20 48 ff 80 00 01 00 00 ff 80 08 01 00 00 48 8b 88 10 01 00 00 48 c7 01 00 00 00 00 e8 ?? ?? ?? ?? 48 8b 44 24 20 48 89 04 24 e8 ?? ?? ?? ?? 48 8b 44 24 20 c6 80 e8 00 00 00 01 48 8b 4c 24 38 48 89 0c 24 48 8b 54 24 40 48 89 54 24 08 e8 ?? ?? ?? ?? 8b 44 24 10 89 44 24 1c 48 8b 4c 24 20 c6 81 e8 00 00 00 00 ff 89 08 01 00 00 ?? 31 d2 87 91 30 03 00 00 e8 ?? ?? ?? ?? 8b 44 24 1c 89 44 24 48 48 8b 6c 24 28 48 83 c4 30 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

