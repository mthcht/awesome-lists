rule VirTool_Win32_LsassDump_Q_2147827003_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/LsassDump.Q!MTB"
        threat_id = "2147827003"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LsassDump"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 e0 8d 14 85 00 00 00 00 8b 45 0c 01 d0 8b 00 8d 95 18 fd ff ff 89 54 24 04 ?? ?? ?? a1 [0-4] ff d0 85 c0 0f [0-5] 8b 45 e0 8d 14 85 00 00 00 00 8b 45 0c 01 d0 8b 00 c7 44 24 04 [0-4] 00 a1 01 ff d0}  //weight: 2, accuracy: Low
        $x_2_2 = {48 8d 14 c5 00 00 00 00 48 8b 85 [0-4] 48 01 d0 48 8b 00 48 8d 55 a0 48 89 c1 48 8b 05 [0-4] ff d0 85 c0 0f 85 [0-4] 8b 85 ec 02 00 00 [0-2] 48 8d 14 c5 00 00 00 00 48 8b 85 [0-4] 48 01 d0 48 8b 00 48 8d 15 ?? ?? 00 00 48 89 c1 48 8b 05 [0-4] ff d0}  //weight: 2, accuracy: Low
        $x_1_3 = {6c 73 61 73 72 76 2e 64 6c 6c 00 6d 73 76 31 5f 30 2e 64 6c 6c 00 74 73 70 6b 67 2e 64 6c 6c 00 77 64 69 67 65 73 74 2e 64 6c 6c 00 6b 65 72 62 65 72 6f 73 2e 64 6c 6c 00 6c 69 76 65 73 73 70 2e 64 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_LsassDump_AF_2147924608_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/LsassDump.AF"
        threat_id = "2147924608"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LsassDump"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7c 24 10 8b 35 ?? ?? ?? ?? 57 6a 00 68 ff ff 1f 00 ff ?? 68 ?? ?? ?? ?? 89 44 24 18 ff ?? ?? ?? ?? ?? 8b f8 85 ff ?? ?? 8b 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 ff ?? 68 ?? ?? ?? ?? 57 a3 ?? ?? ?? ?? ff ?? 8b 35}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 20 ff ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 8d ?? ?? ?? 50 ?? ?? ?? ?? ?? 6a 00 ff ?? ?? ?? ?? ?? 8b 44 24 60 8b 4c 24 64 6a 00 6a 00 6a 10 89 44 24 78 ?? ?? ?? ?? 50 6a 00 ff 74 24 50 c7 84 24 80 00 00 00 01 00 00 00 89 8c 24 88 00 00 00 c7 84 24 8c 00 00 00 02 00 00 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_LsassDump_B_2147952497_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/LsassDump.B"
        threat_id = "2147952497"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LsassDump"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 2f 00 70 00 69 00 64 00 20 00 29 03 03 00}  //weight: 1, accuracy: Low
        $x_1_2 = {20 00 2f 00 66 00 69 00 6c 00 65 00 20 00 29 03 03 00}  //weight: 1, accuracy: Low
        $x_1_3 = {20 00 2f 00 74 00 79 00 70 00 65 00 20 00 29 03 03 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

