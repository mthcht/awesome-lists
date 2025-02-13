rule VirTool_Win32_Herpaderping_A_2147776958_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Herpaderping.A!MTB"
        threat_id = "2147776958"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Herpaderping"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 57 6a 00 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 74 d8 eb d2}  //weight: 1, accuracy: Low
        $x_1_2 = {56 57 8b 3d ?? ?? ?? ?? 51 52 53 ff ?? 85 c0 74 17 56 6a 04 8d ?? ?? ?? 50 8b 44 24 48 83 c0 10 50 53 ff ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {be 80 04 00 00 8d ?? ?? ?? ?? ?? 56 57 50 e8 ?? ?? ?? ?? 83 c4 0c 8d ?? ?? ?? ?? ?? 57 56 50 ff b5 30 ff ff ff ff 75 e0 ff 15 ?? ?? ?? ?? 85 c0 75 19 ff 15 ?? ?? ?? ?? 0f b7 f0 81 ce 00 00 07 80 85 c0 0f 4e f0}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 04 68 00 30 00 00 8b b8 ?? ?? ?? ?? 03 38 57 56 53 ff 15 ?? ?? ?? ?? 8b d0 89 54 24 34 85 d2 74 ?? 8b 4c 24 30 39 71 48 74 ?? 8b 41 04 03 c2 89 41 48 8b 4c 24 30 8b 54 24 34}  //weight: 1, accuracy: Low
        $x_1_5 = {ff b5 9c fa ff ff 89 45 ?? ff 75 e0 50 68 ff ff 1f 00 8d ?? ?? 50 ff 15 ?? ?? ?? ?? 8b f0 85 f6 79 08 81 ce 00 00 00 10}  //weight: 1, accuracy: Low
        $x_1_6 = {c6 45 fc 03 ff 75 cc 6a 04 6a ff 50 68 ff ff 1f 00 8d 45 e0 50 ff 15 ?? ?? ?? ?? 8b f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Herpaderping_A_2147776958_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Herpaderping.A!MTB"
        threat_id = "2147776958"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Herpaderping"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b cb 4c 89 7c 24 20 49 8b cc ff 15 ?? ?? ?? ?? 85 c0 74 83 48 8b 55 88 4c ?? ?? ?? ?? 48 83 c2 20 4c 89 7c 24 20 41 b9 08 00 00 00 49 8b cc ff 15 ?? ?? ?? ?? 85 c0 0f 84 5a ff ff ff 48 8b 57 18 48 83 fa 08 72 10 48 8b 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {bb c8 07 00 00 44 8b c3 33 d2 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 4c 89 7c 24 20 44 8b cb 4c 8d ?? ?? ?? ?? ?? 48 8b 95 a8 00 00 00 48 8b 8d d0 08 00 00 ff 15 ?? ?? ?? ?? 85 c0 75 19 ff 15 ?? ?? ?? ?? 0f b7 d8 81 cb 00 00 07 80 85 c0 0f 4e d8}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 44 24 70 41 b9 00 30 00 00 33 d2 c7 44 24 20 04 00 00 00 49 8b cc 8b 18 48 03 98 f0 03 00 00 4c 8b c3 ff 15 ?? ?? ?? ?? 48 89 44 24 78 48 8b d0 48 85 c0 75 42}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 85 e0 08 00 00 4c 89 ad d0 08 00 00 44 89 bd d8 08 00 00 c7 85 e0 08 00 00 01 00 00 00 44 89 7c 24 40 4c 89 7c 24 38 4c 89 7c 24 30 48 8b 85 c0 08 00 00 48 89 44 24 28 c7 44 24 20 04 00 00 00 4d 8b cd 45 33 c0 ba ff ff 1f 00 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b d8 85 c0 0f 88 89 00 00 00 48 8b 8d c0 08 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {4c 89 bd 30 09 00 00 4c 89 ad 28 09 00 00 4c 89 7c 24 50 4c 89 7c 24 48 4c 89 7c 24 40 4c 89 7c 24 38 44 89 7c 24 30 4c 89 7c 24 28 4c 89 74 24 20 4c 8b 8d d0 08 00 00 45 33 c0 ba ff ff 1f 00 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b d8 85 c0 79 06 0f ba eb 1c eb 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Herpaderping_2147781491_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Herpaderping"
        threat_id = "2147781491"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Herpaderping"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 ec 00 00 00 00 6a 04 6a ff 6a 00 68 ff ff 1f 00 50 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 68 b4 77 43 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 fc 07 68 00 00 00 01 6a 02 6a 00 6a 00 68 1f 00 0f 00 50 c7 45 e4 00 00 00 00 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 56 8b 35 ?? ?? ?? ?? 50 52 57 ?? ?? 85 c0 ?? ?? 8b 4b 04 ba 61 03 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 7d e8 6a 00 57 ff 75 ec 6a 04 6a 00 53 ff 15 ?? ?? ?? ?? 8b f0 85 f6}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 45 e8 8b bd 50 ff ff ff 6a 04 68 00 30 00 00 8b b0 ?? ?? ?? ?? 03 30 56 6a 00 57 ff 15 ?? ?? ?? ?? 8b d0 89 55 88 85 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

