rule VirTool_Win32_Alanzoh_D_2147832000_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Alanzoh.D"
        threat_id = "2147832000"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Alanzoh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 13 8b 6b 04 0f b6 14 2a 8b 6b 0c 30 54 0d 00 8b 53 04 8b 4b 10 83 c2 01 89 53 04 83 c1 01 89 4b 10 3b 53 08}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 48 0c 00 00 00 c7 44 24 50 01 00 00 00 c7 44 24 4c 00 00 00 00 c7 44 24 44 00 00 00 00 c7 44 24 40 00 00 00 00 8d ?? ?? ?? 8d ?? ?? ?? 8d ?? ?? ?? 6a 00 51 50 56 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Alanzoh_E_2147832004_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Alanzoh.E"
        threat_id = "2147832004"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Alanzoh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 e0 89 44 24 08 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 [0-4] 50 68 01 01 00 00 6a 08 68 [0-4] 68 02 00 00 80 ff 15 f8 6d 49 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 6c 24 2c 6a 40 68 00 30 00 00 55 6a 00 56 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 89 c7 89 e0 50 55 ff 74 24 38 57 56 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 6a 00 6a 00 6a 00 57 6a 00 6a 00 56 ff 15 d8 6b 49 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 14 6a 01 e8 ?? ?? ?? ?? 83 c4 08 89 47 04 83 ec 10 0f 28 05 c0 d3 46 00 0f 11 04 24 ff 15 ?? ?? ?? ?? 89 c6 8b 47 04 89 70 10 ff 77 04 ff 37 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 44 24 20 83 ec 18 8d 4c ?? ?? 89 4c 24 14 0f 28 05 f0 d3 ?? ?? 0f 11 44 24 04 89 04 24 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Alanzoh_F_2147832006_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Alanzoh.F"
        threat_id = "2147832006"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
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
        $x_1_5 = {89 c7 01 df 0f 10 05 ?? ?? ?? ?? 0f 29 84 24 e0 02 00 00 0f 10 05 ?? ?? ?? ?? 0f 29 84 24 d0 02 00 00 0f 10 05 ?? ?? ?? ?? 0f 29 84 24 c0 02 00 00 f3 0f 6f 05 ?? ?? ?? ?? 66 0f 7f 84 24 b0 02 00 00 8d 9c 24 b0 02 00 00 53 e8 ?? ?? ?? ?? 83 c4 04 01 e0 05 b0 02 00 00 50 6a 20 89 7c 24 1c 57 e8 ?? ?? ?? ?? 83 c4 0c 68 00 40 00 00 53 e8 ?? ?? ?? ?? 83 c4 08 84 c0 0f 84 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 83 c4 04 85 c0 0f 84 ?? ?? ?? ?? 89 c7 6a 01 68 00 10 00 00 e8 ?? ?? ?? ?? 83 c4 08}  //weight: 1, accuracy: Low
        $x_1_6 = {83 c4 04 01 e0 05 28 05 00 00 8b 4c 24 14 83 c1 05 50 6a 1e 51 e8 ?? ?? ?? ?? 83 c4 0c 57 e8 ?? ?? ?? ?? 83 c4 04 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

