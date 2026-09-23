rule VirTool_Win32_SuspLummaInj_B_2147974822_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspLummaInj.B"
        threat_id = "2147974822"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLummaInj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 0c 37 83 f8 5c 74 05 83 f8 2f 75 08 c6 44 0c 37 00 49 eb ?? 6a 5c 57 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {f2 0f 10 05 ?? ?? ?? ?? 0f 11 00 0f 57 c0 0f 11 44 24 0c 0f 11 04 24 89 f1 6a 00 6a 14 50 68 03 20 01 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 40 04 01 00 00 00 89 e2 83 22 00 89 f1 52 6a 10 50 68 1f 20 01 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = {83 60 04 00 c7 00 59 01 00 00 8d 4c 24 04 83 21 00 6a 00 68 00 00 00 08 6a 40 50 6a 00 6a 0e 51 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_SuspLummaInj_C_2147976849_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspLummaInj.C"
        threat_id = "2147976849"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLummaInj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 20 e0 93 04 00 ba 98 3a 00 00 48 89 f9 41 b8 30 75 00 00 41 b9 e0 93 04 00 ff d6 b8 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 20 e0 93 04 00 ba 98 3a 00 00 48 89 f9 41 b9 e0 93 04 00 41 b8 30 75 00 00 ff d6 b8 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 44 24 20 e0 93 04 00 ba 98 3a 00 00 41 b9 e0 93 04 00 48 89 f9 41 b8 30 75 00 00 ff d6 b8 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {72 69 70 7c 60 67 76 76 7f 3d 70 7c 7e}  //weight: 1, accuracy: High
        $x_1_5 = {5a 4e 47 44 54 56 52 19 54 58 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win32_SuspLummaInj_C_2147976849_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspLummaInj.C"
        threat_id = "2147976849"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLummaInj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 7c 24 28 2a 75 ?? 4b 8d 04 3c 80 38 30 75 ?? 4b 8d 04 3c 80 78 01 78 75 ?? b8 02 00 00 00 48 83 f8 2a 0f 84 ?? ?? ?? ?? 4b 8d 0c 3c 8a 0c 01 48 ff c0 8d 51 d0 80 e1 df 80 c1 bf 80 f9 06 0f 92 c1 80 fa 0a 0f 92 c2 08 ca 75}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 20 40 00 00 00 41 b8 ?? ?? ?? ?? 48 8b 4c 24 ?? 31 d2 41 b9 00 30 00 00 ff d7 48 89 84 24 ?? ?? ?? ?? 48 85 c0 0f 84}  //weight: 1, accuracy: Low
        $x_1_3 = {83 e6 1f 48 83 c6 04 0f b7 c0 c1 e8 05 48 83 c5 02 f7 d0 48 0f bf c0 49 01 c7 45 31 f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_SuspLummaInj_C_2147976849_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspLummaInj.C"
        threat_id = "2147976849"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLummaInj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 4d 00 00 00 41 ff d6 41 89 c5 b9 4c 00 00 00 41 ff d6 41 89 c7 b9 4e 00 00 00 41 ff d6 89 c3 b9 4f 00 00 00 41 ff d6 41 89 c6}  //weight: 1, accuracy: High
        $x_1_2 = {41 ff d5 89 c5 b9 f4 01 00 00 41 ff d7 41 ff d5 39 e8 74 ?? 89 c3 31 c9 ff d6 89 dd 85 c0 74 ?? b9 0d 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 01 f8 80 38 30 75 ?? 48 8b 44 24 ?? 48 01 f8 80 78 01 78 75 ?? b8 02 00 00 00 48 83 f8 2a}  //weight: 1, accuracy: Low
        $x_1_4 = {31 c9 ff d6 85 c0 74 ?? ff 94 24 ?? ?? ?? ?? b9 0d 00 00 00 4c 89 e2 ff 94 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_SuspLummaInj_C_2147976849_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspLummaInj.C"
        threat_id = "2147976849"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLummaInj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 f8 2a 48 89 c6 48 89 44 24 30 75 ?? 41 80 3f 30 75 ?? 41 80 7f 01 78 75 ?? b8 02 00 00 00 48 83 f8 2a 0f 84 ?? ?? ?? ?? 41 8a 0c 07 89 ca 80 e2 df 80 c1 d0 80 f9 0a 0f 92 c1 80 c2 bf 80 fa 06 0f 92 c2 08 ca 48 ff c0 84 d2 75}  //weight: 1, accuracy: Low
        $x_1_2 = {45 31 c0 48 8d 7c 24 58 b9 40 00 00 00 31 c0 f3 ab 40 f6 dd 40 0f b6 c5 48 8d 0d}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 f3 41 0f b6 34 2e 41 0f b6 4c 2e 01 c1 e1 08 09 f1 83 e6 1f 48 83 c6 04 48 83 c5 02 0f b7 c9 c1 e9 05 f7 d9 48 0f bf c9 4c 8d 34 08 49 ff ce 48 83 ee 01 72 ?? 4c 3b 74 24 58 0f 83 ?? ?? ?? ?? 48 8b 44 24 68 42 8a 14 30 48 8b 05 ?? ?? ?? ?? 4c 89 f9 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_SuspLummaInj_D_2147977385_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspLummaInj.D"
        threat_id = "2147977385"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLummaInj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 84 24 a0 00 00 00 48 8b 8c 24 a0 00 00 00 e8 ?? ?? ?? ?? 48 89 84 24 80 00 00 00 48 8b 05 ?? ?? ?? ?? 48 8b 00 48 89 84 24 10 01 00 00 48 8b 8c 24 80 00 00 00 ff 94 24 10 01 00 00 89 44 24 64 48 63 44 24 64 41 b9 1f 00 00 00 4c 8d 05 ?? ?? ?? ?? 48 8b d0 48 8b 8c 24 80 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 08 00 00 00 48 6b c0 00 48 b9 50 00 4f 00 53 00 54 00}  //weight: 1, accuracy: High
        $x_1_3 = {b8 08 00 00 00 48 6b c0 00 48 b9 5c 5c 2e 5c 70 69 70 65}  //weight: 1, accuracy: High
        $x_1_4 = {b8 08 00 00 00 48 6b c0 00 48 b9 43 3a 5c 57 69 6e 64 6f 48 89 8c 04 ?? ?? ?? ?? b8 08 00 00 00 48 6b c0 01 48 b9 77 73 5c 73 70 6c 77 6f 48 89 8c 04 ?? ?? ?? ?? b8 08 00 00 00 48 6b c0 02 48 b9 77 36 34 2e 65 78 65 00 48 89 8c 04}  //weight: 1, accuracy: Low
        $x_1_5 = {b8 08 00 00 00 48 6b c0 00 48 b9 5c 65 78 70 6c 6f 72 65 48 89 8c 04 ?? ?? ?? ?? b8 08 00 00 00 48 6b c0 01 48 b9 72 2e 65 78 65 00 00 00 48 89 8c 04}  //weight: 1, accuracy: Low
        $x_1_6 = {48 8b 54 24 ?? 48 8b 4c 24 ?? ff 94 24 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 48 8b 80 28 03 00 00 48 89 84 24 ?? ?? ?? ?? 4c 8b 44 24 ?? 48 8b 54 24 ?? 48 8b 4c 24 ?? ff 94 24 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 48 8b 80 e0 03 00 00 48 89 84 24 ?? ?? ?? ?? 48 8b 4c 24 ?? ff 94 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_SuspLummaInj_E_2147977857_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspLummaInj.E"
        threat_id = "2147977857"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLummaInj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 ff ff 1f 00 31 d2 41 89 f0 41 ff d6}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 20 40 00 00 00 48 89 d9 31 d2 4c 8b 84 24 ?? ?? ?? ?? 41 b9 00 30 00 00 ff d7}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8d 84 24 ?? ?? ?? ?? 48 89 44 24 20 48 89 d9 48 8b 94 24 ?? ?? ?? ?? 4c 89 fe 4d 89 f8 4c 8b 4c 24 ?? 41 ff d4 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 03 ac 24 ?? ?? ?? ?? 48 83 64 24 30 00 83 64 24 28 00 48 83 64 24 20 00 48 89 d9 31 d2 45 31 c0 4d 89 e9 ff 94 24 ?? ?? ?? ?? 48 85 c0 74 ?? 48 89 c1 ff 94 24}  //weight: 1, accuracy: Low
        $x_1_5 = {48 8d 7c 24 ?? 41 b8 ?? ?? ?? ?? 48 89 f9 41 b1 ?? ff d0 4c 8b 6f 10 48 8b 05 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 4c 8d bc 24 ?? ?? ?? ?? 41 b8 ?? ?? ?? ?? 4c 89 f9 41 b1 ?? ff d0 4d 8b 67 10 48 8b 05 ?? ?? ?? ?? b9 ?? ?? ?? ?? 4c 89 ea 41 b8 ?? ?? ?? ?? 4d 89 e1 ff d0 49 89 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

