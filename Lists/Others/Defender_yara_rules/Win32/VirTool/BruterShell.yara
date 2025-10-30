rule VirTool_Win32_BruterShell_A_2147899112_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/BruterShell.A"
        threat_id = "2147899112"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "BruterShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 23 52 87 a8 4c 89 e1 48 89 84 ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {ba a4 83 d1 35 48 89 d9 e8}  //weight: 1, accuracy: High
        $x_1_3 = {41 bd 6c 6c 00 00 41 54 49 89 d4 ba 77 69 00 00 57 bf 6c 6c 00 00 56 be 79 70 00 00 53 44 89 c3 41 b8 63 72 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {41 b9 74 2e 00 00 41 ba 32 2e 00 00 41 bb 6e 69 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_BruterShell_A_2147899112_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/BruterShell.A"
        threat_id = "2147899112"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "BruterShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 79 01 8b 75 ?? 80 79 02 d1 75 ?? 41 80 f8 b8 75 ?? 80 79 06 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {48 b8 61 64 76 61 70 69 33 32 4c 89 e9 48 89 44 24 60 e8}  //weight: 1, accuracy: High
        $x_1_3 = {4d 8b 04 24 ba c0 21 1d be 4c 89 e1 e8}  //weight: 1, accuracy: High
        $x_1_4 = {48 c7 c2 ff ff ff ff c7 44 24 ?? 04 00 00 00 c7 44 24 ?? 00 30 00 00 [0-16] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_BruterShell_A_2147899112_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/BruterShell.A"
        threat_id = "2147899112"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "BruterShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 79 01 8b 75 ?? 80 79 02 d1 75 ?? 41 80 f8 b8 75 ?? 80 79 06 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {48 b8 61 64 76 61 70 69 33 32 4c 89 e9 48 89 44 24 60 e8}  //weight: 1, accuracy: High
        $x_1_3 = {c7 44 24 38 77 73 32 5f 66 44 89 ?? 24 3c}  //weight: 1, accuracy: Low
        $x_1_4 = {48 c7 c2 ff ff ff ff c7 44 24 ?? 04 00 00 00 c7 44 24 ?? 00 30 ?? 00 4c 89 6c 24 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_BruterShell_A_2147899112_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/BruterShell.A"
        threat_id = "2147899112"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "BruterShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 78 05 e8 75 ?? 80 78 06 03 75 ?? 80 78 0d 8b 75 ?? 80 78 0e d4 75 ?? 0f b6 50 02}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 04 89 4d 39 8c 89 44 24 08 e8}  //weight: 1, accuracy: High
        $x_1_3 = {89 14 24 c7 44 24 ?? 50 4f 53 54 c6 44 24 ?? 00 c7 44 24 ?? 7b 22 61 72 c7 44 24 ?? 63 68 22 3a}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 44 24 04 aa fc 0d 7c [0-128] c7 44 24 04 bd ca 3b d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_BruterShell_A_2147899112_4
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/BruterShell.A"
        threat_id = "2147899112"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "BruterShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 bd 6c 6c 00 00 41 54 49 89 d4 ba 77 69 00 00 57 bf 6c 6c 00 00 56 be 79 70 00 00 53 44 89 c3 41 b8 63 72 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {41 b9 74 2e 00 00 41 ba 32 2e 00 00 41 bb 6e 69 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {80 79 01 8b 75 ?? 80 79 02 d1 75 ?? 41 80 f8 b8 75 ?? 80 79 06 00 75}  //weight: 1, accuracy: Low
        $x_1_4 = {48 83 c1 01 48 39 c8 74 ?? 80 39 0f 75 ?? 80 79 01 05 75 ?? 80 79 02 c3 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_BruterShell_A_2147899112_5
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/BruterShell.A"
        threat_id = "2147899112"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "BruterShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 04 26 25 19 3e 89 44 24 08 c7 04 24 00 00 00 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {80 78 05 e8 75 ?? 80 78 06 03 75 ?? 80 78 0d 8b 75 ?? 80 78 0e d4 75 ?? 0f b6 50 02}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 04 bd ca 3b d3 89 44 24 08 8b 84 24 ?? 00 00 00 89 04 24 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {89 44 24 08 c7 44 24 04 ff ff ff ff 89 3c 24 e8}  //weight: 1, accuracy: High
        $x_1_5 = {c7 44 24 04 b8 0a 4c 53 89 44 24 08 e8}  //weight: 1, accuracy: High
        $x_1_6 = {c7 44 24 04 89 4d 39 8c 89 44 24 08 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_BruterShell_A_2147899112_6
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/BruterShell.A"
        threat_id = "2147899112"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "BruterShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d2 31 c0 39 13 7e 22 48 8b 4c 24 68 4c 63 c8 47 8a 0c 08 48 01 d1 44 30 09 83 f8 07 74 04 ff c0 eb 02 31 c0 48 ff c2 eb da 48 8d 44 24 64 49 89 e8 4c 89 ea 48 83 c9 ff 41 b9 20 00 00 00 48 89 44 24 20 ff d7 48 8b 44 24 68 48 8d 4c 24 78 45 31 c0 ba ff 03 1f 00 49 83 c9 ff 48 c7 44 24 50 00 00 00 00 48 c7 44 24 48 00 00 02 00 48 c7 44 24 40 00 00 02 00 48 c7 44 24 38 00 00 00 00 c7 44 24 30 00 00 00 00 48 c7 44 24 28 00 00 00 00 48 89 44 24 20 41 ff d4 45 31 c0 31 d2 48 83 c9 ff ff d6}  //weight: 1, accuracy: High
        $x_1_2 = {31 c0 31 d2 39 15 ?? ?? ?? ?? 7e 1a 8b 4d dc 8a 98 ?? ?? ?? ?? 01 d1 30 19 83 f8 07 74 03 40 eb 02 31 c0 42 eb de 8d 45 d8 c7 44 24 0c 20 00 00 00 89 44 24 10 8b 45 d4 89 7c 24 08 89 74 24 04 c7 04 24 ff ff ff ff ff d0 8b 45 dc 83 ec 14 89 44 24 10 8d 45 e4 89 04 24 8b 45 cc c7 44 24 28 00 00 00 00 c7 44 24 24 00 00 02 00 c7 44 24 20 00 00 02 00 c7 44 24 1c 00 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 0c ff ff ff ff c7 44 24 08 00 00 00 00 c7 44 24 04 ff 03 1f 00 ff d0 8b 45 d0 83 ec 2c c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 c7 04 24 ff ff ff ff ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

