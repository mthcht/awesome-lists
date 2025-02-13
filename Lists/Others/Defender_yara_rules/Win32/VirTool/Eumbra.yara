rule VirTool_Win32_Eumbra_A_2147757582_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Eumbra.A!!Eumbra.gen!A"
        threat_id = "2147757582"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Eumbra"
        severity = "Critical"
        info = "Eumbra: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 31 c2 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 f0 72 cd 48 8b 55 e8 48 8b 45 f8 48 01 d0 c6 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {70 61 79 6c 6f 61 64 3d [0-4] 2f 77 69 6e 64 6f 77 73 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 00 73 00 74 00 61 00 67 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {50 00 4f 00 53 00 54 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "Blocked: " ascii //weight: 1
        $x_1_6 = "WinHttpQueryDataAvailable" ascii //weight: 1
        $x_1_7 = "beacon.exe" ascii //weight: 1
        $x_1_8 = {c7 44 24 30 00 01 80 00 48 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 [0-32] 48 89 45 ?? 48 83 7d ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Eumbra_A_2147757582_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Eumbra.A!!Eumbra.gen!A"
        threat_id = "2147757582"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Eumbra"
        severity = "Critical"
        info = "Eumbra: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 31 c2 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 f0 72 cd 48 8b 55 e8 48 8b 45 f8 48 01 d0 c6 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {2f 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 00 74 00 61 00 73 00 6b 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {50 00 4f 00 53 00 54 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "username=%s&domain=%s&machine=%s" ascii //weight: 1
        $x_1_6 = "Blocked: " ascii //weight: 1
        $x_1_7 = "WinHttpQueryDataAvailable" ascii //weight: 1
        $x_1_8 = "beacon.exe" ascii //weight: 1
        $x_1_9 = {c7 44 24 30 00 01 80 00 48 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 [0-32] 48 89 45 ?? 48 83 7d ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_10 = "{\"id\":\"%s\",\"opcode\":%d,\"data\":\"%s\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Eumbra_A_2147767613_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Eumbra.A!MTB"
        threat_id = "2147767613"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Eumbra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 38 01 74 4b 31 c0 48 83 c4 28 c3 0f 1f 40 00 b9 02 00 00 00 e8 0e 1b 00 00 eb c8 0f 1f 40 00 0f b7 50 18 66 81 fa 0b 01 74 3d 66 81 fa 0b 02 75 95 83 b8 84 00 00 00 0e 76 8c 8b 90 f8 00 00 00 31 c9 85 d2 0f 95 c1 e9 7a ff ff ff 0f 1f 00 48 8d 0d 79 08 00 00 e8 44 0f 00 00 31 c0 48 83 c4 28 c3 0f 1f 44 00 00 83 78 74 0e 0f 86 55 ff ff ff 44 8b 80 e8 00 00 00 31 c9 45 85 c0 0f 95 c1 e9 41 ff ff ff 66 2e 0f 1f 84 00 00 00 00 00 48 83 ec 38 48 8b 05 45}  //weight: 1, accuracy: High
        $x_1_2 = {48 39 de 74 df 0f 1f 44 00 00 48 8b 03 48 85 c0 74 02 ff d0 48 83 c3 08 48 39 de 75 ed b8 01 00 00 00 48 83 c4 28 5b 5e c3 66 0f 1f 84 00 00 00 00 00 e8 fb 0c 00 00 b8 01 00 00 00 48 83 c4 28 5b 5e c3 66 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 31 c0 c3 90 90 90 90 90 90 90 90 90 90 90 90 90 56 53 48 83 ec 78 0f 11 74 24 40 0f 11 7c 24 50 44 0f 11 44 24 60 83 39 06 0f 87 cd 00 00 00 8b 01 48 8d 15 0c}  //weight: 1, accuracy: High
        $x_1_3 = {48 83 c0 18 90 48 8b 10 49 39 d4 72 14 4c 8b 40 08 45 8b 40 08 4c 01 c2 49 39 d4 0f 82 8b 00 00 00 83 c1 01 48 83 c0 28 39 f9 75 d9 4c 89 e1 e8 01 0d 00 00 48 89 c5 48 85 c0 0f 84 77 01 00 00 48 8b 05 b6}  //weight: 1, accuracy: High
        $x_1_4 = {4c 89 e0 48 29 d8 48 83 f8 07 7e 91 8b 13 48 83 f8 0b 0f 8f 4b 01 00 00 85 d2 0f 85 cb 01 00 00 8b 43 04 85 c0 0f 85 c0 01 00 00 8b 53 08 83 fa 01 0f 85 1c 02 00 00 48 83 c3 0c 4c 8d 7d a8 4c 8b 2d c5}  //weight: 1, accuracy: High
        $x_1_5 = {7c d1 e9 3e fe ff ff 0f 1f 40 00 85 d2 0f 85 80 00 00 00 8b 43 04 89 c7 0b 7b 08 0f 85 aa fe ff ff 8b 53 0c 48 83 c3 0c e9 93 fe ff ff 66 0f 1f 44 00 00 41 83 f8 40 0f 85 a7 00 00 00 48 8b 01 41 b8 08 00 00 00 4c 89 ff 48 29 d0 4c 89 fa 4c 01 c8 48 89 45 a8 e8 b8 fb ff ff e9 d3 fe ff ff 0f 1f 00 8b 01 4c 89 ff 49 89 c0 4c 09 f0 45 85 c0 49 0f 49 c0 41 b8 04 00 00 00 48 29 d0 4c 89 fa 4c 01 c8 48 89 45 a8 e8 86 fb ff ff e9 a1 fe ff ff 90 4c 39 e3 0f 83 a9 fd ff ff 49 83 ec 01 4c 8b 2d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

