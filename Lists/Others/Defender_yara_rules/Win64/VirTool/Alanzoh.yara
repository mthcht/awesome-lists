rule VirTool_Win64_Alanzoh_A_2147782054_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Alanzoh.A"
        threat_id = "2147782054"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Alanzoh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 57 56 83 ec 08 8b 0d 34 50 ?? ?? 8b 44 24 18 31 e1 89 4c 24 04 c7 04 24 00 00 00 00 50 6a 00 6a 2a ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 8b 5c 24 1c 89 c6 6a 40 68 00 30 00 00 53 6a 00 50 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 89 c7 89 e0 50 53 ff 74 24 28 57 56 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 6a 00 6a 00 6a 00 57 6a 00 6a 00 56 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {55 89 e5 53 83 e4 f0 83 ec 30 a1 34 50 ?? ?? 0f 57 c0 31 e8 89 44 24 20 c7 44 24 0c 00 00 00 00 0f 29 44 24 10 ff 15 ?? ?? ?? ?? 8d 4c ?? ?? 51 6a 28 50 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 8d 44 ?? ?? 50 68 86 01 ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? c7 44 24 10 01 00 00 00 c7 44 24 1c 02 00 00 00 8d 44 ?? ?? 6a 00 6a 00 6a 10 50 6a 00 ff 74 24 20 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 1b 85 db ?? ?? 8d 74 ?? ?? c7 44 24 70 00 00 00 00 56 6a 00 ff 15 ?? ?? ?? ?? 8b 5c 24 14 83 f8 6f 0f ?? ?? ?? ?? ?? 6a 01 ff 74 24 74 e8 ?? ?? ?? ?? 83 c4 08 85 c0 0f ?? ?? ?? ?? ?? 56 50 89 44 24 18 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {89 c7 50 68 eb ff ?? ?? 53 e8 ?? ?? ?? ?? 85 c0 0f ?? ?? ?? ?? ?? 8b 74 24 70 83 7c 24 68 00 0f ?? ?? ?? ?? ?? 31 c0 89 7c 24 18}  //weight: 1, accuracy: Low
        $x_1_5 = {55 89 e5 53 57 56 83 e4 f0 b8 b0 41 00 00 e8 ?? ?? ?? ?? a1 34 50 ?? ?? 8d 74 ?? ?? 0f 57 c0 8d 4c ?? ?? 31 e8 89 84 24 a8 41 00 00 c7 44 24 24 0c 00 00 00 c7 44 24 2c 01 00 00 00 0f 29 44 24 70 0f 29 44 24 60 0f 29 44 24 50 0f 29 44 24 40 c7 84 24 84 00 00 00 00 00 00 00 c7 84 24 80 00 00 00 00 00 00 00 0f 29 44 24 30 c7 44 24 20 00 00 00 00 c7 44 24 1c 00 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 28 00 00 00 00 c7 44 24 10 00 00 00 00 8d 44 24 14 6a 00 56 50 51 ff 15}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 8c bc a8 01 00 00 85 c9 ?? ?? c7 84 24 98 00 00 00 00 00 00 00 c7 84 24 94 00 00 00 00 00 00 00 51 6a 00 68 d0 04 00 00 ff 15 ?? ?? ?? ?? 85 c0 89 84 24 9c 00 00 00 ?? ?? 68 04 01 00 00 6a 00 8d 9c ?? ?? ?? ?? ?? 53 89 c6 e8 ?? ?? ?? ?? 83 c4 0c 68 04 01 00 00 53 89 74 24 10 56 e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8b 44 24 0c ff 70 10 53 e8 ?? ?? ?? ?? 83 c4 08 85 c0 0f 84 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8d 8c ?? ?? ?? ?? ?? 51 50 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8d 84 ?? ?? ?? ?? ?? 50 ff b4 bc ac 01 00 00 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8b 84 24 94 00 00 00 3b 84 24 98 00 00 00 0f 85 ?? ?? ?? ?? 8b 7c 24 14 c7 84 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule VirTool_Win64_Alanzoh_D_2147831999_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Alanzoh.D"
        threat_id = "2147831999"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Alanzoh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5e 08 0f b6 14 1a 48 8b 5e 18 30 14 0b 8b 56 08 83 c2 01 89 56 08 8b 4e 20 83 c1 01 89 4e 20 48 39 56 10}  //weight: 1, accuracy: High
        $x_1_2 = {c7 84 24 c0 00 00 00 18 00 00 00 c7 84 24 d0 00 00 00 01 00 00 00 48 c7 84 24 c8 00 00 00 00 00 00 00 0f 29 b4 24 40 03 00 00 48 8d ?? ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? ?? 4c 8d ?? ?? ?? ?? ?? ?? 45 31 c9 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Alanzoh_E_2147832003_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Alanzoh.E"
        threat_id = "2147832003"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Alanzoh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 31 e0 48 89 44 24 40 48 c7 44 24 38 00 00 00 00 c7 44 24 34 00 00 00 00 48 8d ?? ?? ?? 48 89 44 24 20 48 8d ?? ?? ?? ?? ?? 48 c7 c1 02 00 00 80 41 b8 08 00 00 00 41 b9 01 01 00 00 ff 15 e2 d1 09 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 20 40 00 00 00 48 89 d9 31 d2 4d 89 f8 41 b9 00 30 00 00 ff 15 ?? ?? ?? ?? 48 85 c0 0f 84 ?? ?? ?? ?? 48 89 c6 48 8d ?? ?? ?? 48 89 44 24 20 48 89 d9 48 89 f2 49 89 f8 4d 89 f9 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 31 ff 48 89 d9 31 d2 45 31 c0 49 89 f1 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 46 08 31 ff 31 c9 ba 01 00 00 00 41 b8 01 00 00 00 45 31 c9 ff 15 ?? ?? ?? ?? 49 89 c6 48 8b 46 08 4c 89 70 18 48 8b 0e 48 8b 56 08 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 44 24 20 01 00 00 00 ba 00 00 00 02 45 31 c0 41 b9 02 00 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Alanzoh_F_2147832005_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Alanzoh.F"
        threat_id = "2147832005"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Alanzoh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "original_session_key" ascii //weight: 1
        $x_1_2 = "key_iteration" ascii //weight: 1
        $x_1_3 = "active_server" ascii //weight: 1
        $x_1_4 = "session_id" ascii //weight: 1
        $x_1_5 = {41 89 c4 41 01 dc 0f 28 05 ?? ?? ?? ?? 0f 29 84 24 60 04 00 00 0f 28 05 ?? ?? ?? ?? 0f 29 84 24 50 04 00 00 0f 28 05 ?? ?? ?? ?? 0f 29 84 24 40 04 00 00 0f 28 05 ?? ?? ?? ?? 0f 29 84 24 30 04 00 00 48 8d ?? ?? ?? ?? ?? ?? 48 89 d9 e8 ?? ?? ?? ?? 4c 8d ?? ?? 49 81 c0 30 04 00 00 ba 20 00 00 00 44 89 e1 e8 ?? ?? ?? ?? 48 89 d9 ba 00 40 00 00 e8 ?? ?? ?? ?? 84 c0 0f 84 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 85 c0 0f 84 ?? ?? ?? ?? 48 89 c3 b9 00 10 00 00 ba 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {41 b8 00 10 00 00 48 89 e9 31 d2 e8 ?? ?? ?? ?? 48 89 e9 e8 ?? ?? ?? ?? 48 89 bc 04 40 08 00 00 48 89 e9 e8 ?? ?? ?? ?? 4c 8d ?? ?? 49 81 c0 40 08 00 00 41 83 c4 05 ba 1e 00 00 00 44 89 e1 e8 ?? ?? ?? ?? 48 89 e9 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

