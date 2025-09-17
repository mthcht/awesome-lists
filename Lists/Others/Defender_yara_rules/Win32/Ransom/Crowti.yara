rule Ransom_Win32_Crowti_A_2147684191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crowti.A"
        threat_id = "2147684191"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crowti"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 a0 00 00 00 e8 18 00 00 00 59 89 45 fc 83 7d fc 00 74 ?? 8b 45 fc 2d ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Crowti_A_2147684191_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crowti.A"
        threat_id = "2147684191"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crowti"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 68 00 30 00 00 8d 4d ?? 51 6a 00 68 ?? ?? ?? ?? 6a ff ff 55}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 51 2c d1 ea 52 8b 45 ?? 8b 48 30 51 e8 ?? ?? ?? ?? 83 c4 08 3b 45 08 75 08 8b 55 ?? 8b 42 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Crowti_B_2147686318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crowti.B"
        threat_id = "2147686318"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crowti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 00 00 01 00 00 00 70 00 75 00 62 00 00 00 73 00 74 00 61 00 72 00 74 00 00 00 66 00 69 00 6e 00 69 00 73 00 68 00 00 00 00 00 75 00 72 00 6c 00 00 00 74 00 6f 00 72 00 75 00 72 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 55 53 45 52 5f 43 4f 44 45 25 00 25 54 4f 52 5f 53 45 52 56 49 43 45 5f 55 52 4c 25 00 00 00 25 53 45 52 56 49 43 45 5f 55 52 4c 25 00}  //weight: 1, accuracy: High
        $x_1_3 = "<title>CryptoDefense" ascii //weight: 1
        $x_1_4 = {3e 43 00 72 79 70 74 6f 44 65 66 c0 65 6e 73 65 3c}  //weight: 1, accuracy: High
        $x_1_5 = {63 72 79 70 74 65 64 20 10 62 79 20 43 01 14 6f 44 65 00 66 65 6e 73 65 20 53 6f 08 66 74 77 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Crowti_B_2147686318_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crowti.B"
        threat_id = "2147686318"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crowti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 0c 68 01 00 01 00 6a 00 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 88 94 00 00 00 ff d1 89 45 f8 83 7d f8 00}  //weight: 1, accuracy: Low
        $x_1_2 = {9b 85 e7 e3 ca 85 53 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Crowti_B_2147686318_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crowti.B"
        threat_id = "2147686318"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crowti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 37 8b 45 fc 83 e0 40 75 1b 8b 4d fc 81 e1 80 00 00 00 75 10 8b 55 fc 83 e2 08 75 08 8b 45 fc 83 e0 04 74 14}  //weight: 1, accuracy: High
        $x_1_2 = {b9 2a 00 00 00 8b 55 f8 66 89 0c 02 8b 45 fc 50 8b 4d f8 51 6a 00 6a 02 6a 02 e8 f3 f9 ff ff 83 c4 14 85 c0 74 07 c7 45 f4 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {b9 02 00 00 00 6b d1 07 b8 2e 00 00 00 8b 4d fc 66 89 04 11 ba 02 00 00 00 c1 e2 03 b8 65 00 00 00 8b 4d fc 66 89 04 11 ba 02 00 00 00 6b c2 09 b9 78 00 00 00 8b 55 fc 66 89 0c 02 b8 02 00 00 00 6b c8 0a ba 65 00 00 00 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_4 = {b8 53 00 00 00 66 89 45 ac b9 59 00 00 00 66 89 4d ae ba 53 00 00 00 66 89 55 b0 b8 54 00 00 00 66 89 45 b2 b9 45 00 00 00 66 89 4d b4 ba 4d 00 00 00 66 89 55 b6 b8 44 00 00 00 66 89 45 b8 b9 52 00 00 00 66 89 4d ba ba 49 00 00 00 66 89 55 bc b8 56 00 00 00 66 89 45 be b9 45 00 00 00 66 89 4d c0 33 d2 66 89 55 c2 c7 45 e4 00 00 00 00 c7 45 c4 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Crowti_B_2147686447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crowti.B!!Crowti.B"
        threat_id = "2147686447"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crowti"
        severity = "Critical"
        info = "Crowti: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 0c 68 01 00 01 00 6a 00 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 88 94 00 00 00 ff d1 89 45 f8 83 7d f8 00}  //weight: 1, accuracy: Low
        $x_1_2 = {9b 85 e7 e3 ca 85 53 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Crowti_B_2147686447_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crowti.B!!Crowti.B"
        threat_id = "2147686447"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crowti"
        severity = "Critical"
        info = "Crowti: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 00 00 01 00 00 00 70 00 75 00 62 00 00 00 73 00 74 00 61 00 72 00 74 00 00 00 66 00 69 00 6e 00 69 00 73 00 68 00 00 00 00 00 75 00 72 00 6c 00 00 00 74 00 6f 00 72 00 75 00 72 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 55 53 45 52 5f 43 4f 44 45 25 00 25 54 4f 52 5f 53 45 52 56 49 43 45 5f 55 52 4c 25 00 00 00 25 53 45 52 56 49 43 45 5f 55 52 4c 25 00}  //weight: 1, accuracy: High
        $x_1_3 = "<title>CryptoDefense" ascii //weight: 1
        $x_1_4 = {3e 43 00 72 79 70 74 6f 44 65 66 c0 65 6e 73 65 3c}  //weight: 1, accuracy: High
        $x_1_5 = {63 72 79 70 74 65 64 20 10 62 79 20 43 01 14 6f 44 65 00 66 65 6e 73 65 20 53 6f 08 66 74 77 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Crowti_B_2147686447_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crowti.B!!Crowti.B"
        threat_id = "2147686447"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crowti"
        severity = "Critical"
        info = "Crowti: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 2a 00 00 00 8b 55 f8 66 89 0c 02 8b 45 fc 50 8b 4d f8 51 6a 00 6a 02 6a 02 e8 f3 f9 ff ff 83 c4 14 85 c0 74 07 c7 45 f4 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {b9 02 00 00 00 6b d1 07 b8 2e 00 00 00 8b 4d fc 66 89 04 11 ba 02 00 00 00 c1 e2 03 b8 65 00 00 00 8b 4d fc 66 89 04 11 ba 02 00 00 00 6b c2 09 b9 78 00 00 00 8b 55 fc 66 89 0c 02 b8 02 00 00 00 6b c8 0a ba 65 00 00 00 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_3 = {b8 53 00 00 00 66 89 45 ac b9 59 00 00 00 66 89 4d ae ba 53 00 00 00 66 89 55 b0 b8 54 00 00 00 66 89 45 b2 b9 45 00 00 00 66 89 4d b4 ba 4d 00 00 00 66 89 55 b6 b8 44 00 00 00 66 89 45 b8 b9 52 00 00 00 66 89 4d ba ba 49 00 00 00 66 89 55 bc b8 56 00 00 00 66 89 45 be b9 45 00 00 00 66 89 4d c0 33 d2 66 89 55 c2 c7 45 e4 00 00 00 00 c7 45 c4 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Crowti_B_2147686447_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crowti.B!!Crowti.B"
        threat_id = "2147686447"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crowti"
        severity = "Critical"
        info = "Crowti: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HELP_DECRYPT.TXT" wide //weight: 1
        $x_1_2 = "HELP_DECRYPT.HTML" wide //weight: 1
        $x_1_3 = "HELP_DECRYPT.URL" wide //weight: 1
        $x_1_4 = "HELP_DECRYPT.PNG" wide //weight: 1
        $x_2_5 = {c6 45 f4 63 c6 45 f5 72 c6 45 f6 79 c6 45 f7 70 c6 45 f8 74 c6 45 f9 31}  //weight: 2, accuracy: High
        $x_2_6 = {c6 45 e4 61 c6 45 e5 6c c6 45 e6 6c c6 45 e7 3d c6 45 e8 25 c6 45 e9 64}  //weight: 2, accuracy: High
        $x_1_7 = {89 45 f8 81 7d f8 1a 00 00 80 0f 84 ?? ?? ?? ?? 81 7d f8 23 00 00 c0 74 ?? 81 7d f8 05 00 00 80 75 ?? 83 7d ec 00 74}  //weight: 1, accuracy: Low
        $x_1_8 = {3d 8b 11 4d c9 75 07 c7 45 e4 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {b8 60 88 06 00 25 00 f0 ff ff 89 45 fc 8b 4d fc 0f b7 11 81 fa 4d 5a 00 00 74 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Crowti_B_2147686447_4
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crowti.B!!Crowti.B"
        threat_id = "2147686447"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crowti"
        severity = "Critical"
        info = "Crowti: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {43 00 52 00 59 00 50 00 54 00 4c 00 49 00 53 00 54 00 00 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 5f 00 49 00 4e 00 53 00 54 00 52 00 55 00 43 00 54 00 49 00 4f 00 4e 00 2e 00 54 00 58 00 54 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {44 00 45 00 43 00 52 00 59 00 50 00 54 00 5f 00 49 00 4e 00 53 00 54 00 52 00 55 00 43 00 54 00 49 00 4f 00 4e 00 2e 00 48 00 54 00 4d 00 4c 00 00 00 00 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 5f 00 49 00 4e 00 53 00 54 00 52 00 55 00 43 00 54 00 49 00 4f 00 4e 00 2e 00 55 00 52 00 4c 00 00 00}  //weight: 10, accuracy: High
        $x_1_3 = {c6 45 f4 63 c6 45 f5 77 c6 45 f6 34 c6 45 f7 30 c6 45 f8 30 c6 45 f9 00 6a 28 e8}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 e8 7b c6 45 e9 25 c6 45 ea 64 c6 45 eb 7c c6 45 ec 25 c6 45 ed 73 c6 45 ee 7c c6 45 ef 25 c6 45 f0 73 c6 45 f1 7d c6 45 f2 00}  //weight: 1, accuracy: High
        $x_2_5 = {c6 45 e0 20 c6 45 e1 44 c6 45 e2 65 c6 45 e3 6c c6 45 e4 65 c6 45 e5 74 c6 45 e6 65 c6 45 e7 20 c6 45 e8 53 c6 45 e9 68 c6 45 ea 61 c6 45 eb 64 c6 45 ec 6f c6 45 ed 77 c6 45 ee 73 c6 45 ef 20 c6 45 f0 2f c6 45 f1 41 c6 45 f2 6c c6 45 f3 6c c6 45 f4 20 c6 45 f5 2f c6 45 f6 51 c6 45 f7 75 c6 45 f8 69 c6 45 f9 65 c6 45 fa 74 c6 45 fb 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Crowti_C_2147687789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crowti.C"
        threat_id = "2147687789"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crowti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {43 00 52 00 59 00 50 00 54 00 4c 00 49 00 53 00 54 00 00 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 5f 00 49 00 4e 00 53 00 54 00 52 00 55 00 43 00 54 00 49 00 4f 00 4e 00 2e 00 54 00 58 00 54 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {44 00 45 00 43 00 52 00 59 00 50 00 54 00 5f 00 49 00 4e 00 53 00 54 00 52 00 55 00 43 00 54 00 49 00 4f 00 4e 00 2e 00 48 00 54 00 4d 00 4c 00 00 00 00 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 5f 00 49 00 4e 00 53 00 54 00 52 00 55 00 43 00 54 00 49 00 4f 00 4e 00 2e 00 55 00 52 00 4c 00 00 00}  //weight: 10, accuracy: High
        $x_1_3 = {c6 45 f4 63 c6 45 f5 77 c6 45 f6 34 c6 45 f7 30 c6 45 f8 30 c6 45 f9 00 6a 28 e8}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 e8 7b c6 45 e9 25 c6 45 ea 64 c6 45 eb 7c c6 45 ec 25 c6 45 ed 73 c6 45 ee 7c c6 45 ef 25 c6 45 f0 73 c6 45 f1 7d c6 45 f2 00}  //weight: 1, accuracy: High
        $x_2_5 = {c6 45 e0 20 c6 45 e1 44 c6 45 e2 65 c6 45 e3 6c c6 45 e4 65 c6 45 e5 74 c6 45 e6 65 c6 45 e7 20 c6 45 e8 53 c6 45 e9 68 c6 45 ea 61 c6 45 eb 64 c6 45 ec 6f c6 45 ed 77 c6 45 ee 73 c6 45 ef 20 c6 45 f0 2f c6 45 f1 41 c6 45 f2 6c c6 45 f3 6c c6 45 f4 20 c6 45 f5 2f c6 45 f6 51 c6 45 f7 75 c6 45 f8 69 c6 45 f9 65 c6 45 fa 74 c6 45 fb 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Crowti_B_2147706956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crowti.gen!B"
        threat_id = "2147706956"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crowti"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 f0 7c c6 45 f1 25 c6 45 f2 64 c6 45 f3 7d}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d f8 8b 55 f4 66 8b 44 4a 02 66 89 45 fc 8b 4d f8 8b 55 f4 8b 45 f8 8b 75 f4 66 8b 04 46 66 89 44 4a 02 8b 4d f8 8b 55 f4 66 8b 45 fc 66 89 04 4a 8b 4d f8 83 c1 01 89 4d f8}  //weight: 1, accuracy: High
        $x_1_3 = "HELP_DECRYPT." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Crowti_P_2147744741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crowti.P!MSR"
        threat_id = "2147744741"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crowti"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/C wmic SHADOWCOPY DELETE" wide //weight: 1
        $x_1_2 = "/C vssadmin.exe delete shadows /all /quiet" wide //weight: 1
        $x_1_3 = "TRY_TO_READ.html" wide //weight: 1
        $x_10_4 = "I am truly sorry to inform you that all your important files are crypted" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Crowti_MKV_2147937068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crowti.MKV!MTB"
        threat_id = "2147937068"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crowti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 ee 08 0f b7 55 fe 52 e8 ?? ?? ?? ?? 83 c4 04 0f b7 c0 33 45 f8 25 ff 00 00 00 33 34 85 ?? ?? ?? ?? 89 75 f8 8b 4d f4 83 c1 02 89 4d f4 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

