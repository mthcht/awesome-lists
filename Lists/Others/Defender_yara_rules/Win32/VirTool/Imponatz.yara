rule VirTool_Win32_Imponatz_A_2147782053_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Imponatz.A"
        threat_id = "2147782053"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Imponatz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 06 8b 4e 04 52 52 52 89 45 dc 8d ?? ?? 50 52 ff 75 e8 89 4d e0 c7 45 d8 01 00 00 00 c7 45 e4 02 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {56 ff 75 14 ff 75 10 e8 ?? ?? ?? ?? 89 45 fc 59 59 85 c0 ?? ?? 8d ?? ?? 51 ff 75 18 50 68 06 30 41 00 ff 75 0c ff 75 08 ff 15 ?? ?? ?? ?? 8b f0 85 f6}  //weight: 1, accuracy: Low
        $x_1_3 = {50 6a 08 56 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 56 ff 15 ?? ?? ?? ?? eb ?? 8d ?? ?? ?? 50 57 57 6a 04 ff 74 24 30 ff 15 ?? ?? ?? ?? 85 c0 0f 85 ?? ?? ?? ?? ff 74 24 24 6a 08 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b f8 85 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {55 8b ec 83 ec 20 a1 04 c0 43 00 33 c5 89 45 f8 53 56 8b f1 33 db 57 39 5e 04 ?? ?? 8d ?? ?? 50 68 7c 81 43 00 53 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Imponatz_A_2147782053_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Imponatz.A"
        threat_id = "2147782053"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Imponatz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 45 d8 4c 8d ?? ?? 48 83 64 24 28 00 45 33 c9 48 83 64 24 20 00 33 d2 48 8b 4d c8 48 89 45 e4 c7 45 ec 02 00 00 00 ff 15 ?? ?? ?? ?? 48 8b 4d c0 ff 15 ?? ?? ?? ?? 48 8b cb ff 15 ?? ?? ?? ?? 48 8d 4d c8 e8 ?? ?? ?? ?? b8 01 00 00 00 48 8b 4d f0 48 33 cc e8 ?? ?? ?? ?? 48 8b 9c 24 80 00 00 00 48 83 c4 70 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 44 24 28 89 5c 24 20 45 8b ce 45 33 c0 ba ff 01 0f 00 48 8b 4c 24 50 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b c8 e8 ?? ?? ?? ?? 48 8b c8 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b 4c 24 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {be 08 00 00 00 4c 8d ?? ?? 8b d6 49 8b ce ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 49 8b ce ff 15 ?? ?? ?? ?? ?? ?? 48 8b 4d e0 48 8d ?? ?? 45 33 c9 48 89 44 24 20 45 33 c0 45 8d ?? ?? 41 8b d5 ff 15 ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 8b 5d d0 ff 15 ?? ?? ?? ?? 44 8b c3 8b d6 48 8b c8 ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b 55 c0 48 8d ?? ?? 0f 57 c0 0f 11 45 c8 e8 ?? ?? ?? ?? 48 8d 4d c8 e8 ?? ?? ?? ?? 85 c0 ?? ?? 4c 8d ?? ?? 33 c9 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Imponatz_A_2147782053_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Imponatz.A"
        threat_id = "2147782053"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Imponatz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 14 83 65 f4 00 8d ?? ?? 83 65 f8 00 50 ff 15 ?? ?? ?? ?? 8b 45 f8 33 45 f4 89 45 fc ff 15 ?? ?? ?? ?? 31 45 fc ff 15 ?? ?? ?? ?? 31 45 fc 8d ?? ?? 50 ff 15 ?? ?? ?? ?? 8b 45 f0 8d ?? ?? 33 45 ec 33 45 fc 33 c1 c9 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 41 08 f3 0f 7e 01 89 44 24 2c 8b 44 24 20 66 0f d6 44 24 24 3b 44 24 28 ?? ?? 3b 5c 24 24 ?? ?? 42 83 c1 0c 3b d6 ?? ?? ?? ?? 8d ?? ?? ?? 50 68 cc 56 40 00 6a 00 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 6a 01 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 44 24 1c 8b 4c 24 20 6a 00 6a 00 6a 00 89 44 24 34 8d ?? ?? ?? 50 6a 00 ff 74 24 20 89 4c 24 44 c7 44 24 48 02 00 00 00 ff 15 ?? ?? ?? ?? ff 74 24 18 8b 35 2c 50 40 00 ff ?? 57 ff ?? ff 74 24 10 6a 08 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b 4c 24 34 b8 01 00 00 00 5f 5e 5b 33 cc e8 ?? ?? ?? ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_4 = {83 7d 08 00 b9 00 00 00 08 8b 3d 14 50 40 00 b8 10 02 00 00 0f 44 c1 c7 45 d4 00 00 00 00 8d ?? ?? 89 45 80 8b 45 cc 0f 57 c0 51 6a 00 6a 00 6a 03 66 0f 13 45 e8 50 89 45 84 89 45 e8 ff ?? ff 75 d4 6a 08 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b 4d d4 8b f0 83 c1 fc 89 75 ec b8 ab aa aa aa f7 e1 8d ?? ?? 50 c1 ea 03 89 16 ff 75 d4 56 6a 03 ff 75 84 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

