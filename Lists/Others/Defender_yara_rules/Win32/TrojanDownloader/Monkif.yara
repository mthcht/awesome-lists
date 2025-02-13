rule TrojanDownloader_Win32_Monkif_A_2147616178_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Monkif.A"
        threat_id = "2147616178"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 c4 18 46 81 fe 00 00 10 00 7c e0}  //weight: 3, accuracy: High
        $x_3_2 = {83 f8 ff 74 22 ?? 8d 45 f4 50 6a 10 ?? ?? e8 ?? ?? ?? ?? ?? 8d 45 f4 50 6a 08 09 00 6a e8 ?? ff 15}  //weight: 3, accuracy: Low
        $x_1_3 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 50 52 4f 54 4f 43 4f 4c 53 5c 46 69 6c 74 65 72 5c 74 65 78 74 2f 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {54 3d 25 64 2c 53 3d 25 64 2c 25 73 2c 46 3d 25 73 2c 00}  //weight: 1, accuracy: High
        $x_2_5 = {4c 6f 63 61 6c 5c 55 49 45 49 00}  //weight: 2, accuracy: High
        $x_1_6 = "%u|%u|%u|%u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Monkif_B_2147616683_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Monkif.B"
        threat_id = "2147616683"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 f8 ff 74 22 ?? 8d 45 f4 50 6a 10 ?? ?? e8 ?? ?? ?? ?? ?? 8d 45 f4 50 6a 08 09 00 6a e8 ?? ff 15}  //weight: 3, accuracy: Low
        $x_3_2 = {6a e8 56 ff 15 ?? ?? ?? ?? 83 f8 ff 74 25 53 8d 45 f4 50 6a 10 8d 45 e4 50 56 e8 ?? ?? ff ff 53 8d 45 f4 50 6a 08}  //weight: 3, accuracy: Low
        $x_1_3 = {25 73 25 73 2e 70 68 70 3f 25 73 3d 25 73 00}  //weight: 1, accuracy: High
        $x_2_4 = {2f 73 6f 64 6f 6d 61 2f 00}  //weight: 2, accuracy: High
        $x_1_5 = "%u|%u|%u|%u" ascii //weight: 1
        $x_1_6 = {71 72 6f 63 65 73 73 33 32 66 69 72 73 74 00 00 7a 72 6f 63 65 73 73 33 32 6e 65 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Monkif_E_2147618161_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Monkif.E"
        threat_id = "2147618161"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b4 00 00 00 75 ?? c7 05 ?? ?? ?? ?? 20 1c 00 00 e9 ?? ff ff ff}  //weight: 2, accuracy: Low
        $x_2_2 = {b4 00 00 00 0f 85 ?? ?? ff ff c7 05 ?? ?? ?? ?? 20 1c 00 00 e9 06 00 81 3d}  //weight: 2, accuracy: Low
        $x_1_3 = {47 6c 6f 62 61 6c 5c 55 49 45 49 00}  //weight: 1, accuracy: High
        $x_1_4 = {54 3d 25 64 2c 53 3d 25 64 2c 25 73 2c 46 3d 25 73 2c 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 50 52 4f 54 4f 43 4f 4c 53 5c 46 69 6c 74 65 72 5c 74 65 78 74 2f 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 64 7c 25 64 7c 25 64 7c 25 64 00}  //weight: 1, accuracy: High
        $x_1_7 = {2f 73 6f 64 6f 6d 61 2f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Monkif_F_2147618419_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Monkif.F"
        threat_id = "2147618419"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {bc 00 00 00 75 ?? c7 05 ?? ?? ?? ?? 78 1c 00 00 eb}  //weight: 2, accuracy: Low
        $x_2_2 = {00 02 00 00 74 de 81 3d ?? ?? ?? ?? 01 02 00 00 74 d2}  //weight: 2, accuracy: Low
        $x_2_3 = {c6 45 f4 4c c6 45 f5 6f c6 45 f6 63 c6 45 f7 61 c6 45 f8 6c c6 45 f9 5c c6 45 fa 55 c6 45 fb 49 c6 45 fc 45 c6 45 fd 49}  //weight: 2, accuracy: High
        $x_1_4 = {ff 45 fc 8b 45 fc 6b c0 60 8d 34 18 33 ff 39 3e 75 cd}  //weight: 1, accuracy: High
        $x_1_5 = {25 73 25 73 2e 70 68 70 3f 25 73 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 75 7c 25 75 7c 25 75 7c 25 75 7c 25 75 7c 25 75 00}  //weight: 1, accuracy: High
        $x_1_7 = {2f 62 61 62 79 6c 6f 6e 2f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Monkif_G_2147618900_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Monkif.G"
        threat_id = "2147618900"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {c6 45 f4 4c c6 45 f5 6f c6 45 f6 63 c6 45 f7 61 c6 45 f8 6c c6 45 f9 5c c6 45 fa 55 c6 45 fb 49 c6 45 fc 45 c6 45 fd 49}  //weight: 4, accuracy: High
        $x_1_2 = {8d 0c 10 8a 4c 0d d0 3a 4c 15 d0 75 06 42 83 fa 20 72 ed 83 fa 20 75 6e}  //weight: 1, accuracy: High
        $x_1_3 = {58 6a 0f 50 cb}  //weight: 1, accuracy: High
        $x_1_4 = {58 b9 0f 00 00 00 51 50 cb}  //weight: 1, accuracy: High
        $x_1_5 = {75 e1 ff 45 fc 8b 45 fc 6b c0 60 8d 34 18 33 ff 39 3e 75 cd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Monkif_H_2147621078_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Monkif.H"
        threat_id = "2147621078"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 0f 00 00 80 79 05 49 83 c9 f0 41 74 04 83 c0}  //weight: 1, accuracy: High
        $x_1_2 = {55 46 ff d7 3b f0 7c e9 5b 5f c6 86 08 00 2c ?? 88 86}  //weight: 1, accuracy: Low
        $x_1_3 = {67 2b 00 00 74 36 6a 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Monkif_I_2147621079_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Monkif.I"
        threat_id = "2147621079"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 99 f7 fb 83 c1 01 8a 04 2a 30 44 31 ff 3b cf 7c ed}  //weight: 1, accuracy: High
        $x_1_2 = {b2 15 80 3c 31 ff 75 0e 38 54 31 01}  //weight: 1, accuracy: High
        $x_2_3 = {57 56 ff d5 33 c9 85 ff 76 1a 8a 04 31 8a d0 f6 d2 32 d0 80 e2 14 f6 d0 32 d0 88 14 31}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Monkif_K_2147624646_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Monkif.K"
        threat_id = "2147624646"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 7d f4 93 08 00 00 74 0c 46 81 fe e8 19 10 00 7c e4}  //weight: 2, accuracy: High
        $x_1_2 = {b8 68 58 4d 56 b9 14 00 00 00 66 ba 58 56 ed}  //weight: 1, accuracy: High
        $x_1_3 = {58 6a 0f 50 cb}  //weight: 1, accuracy: High
        $x_2_4 = {8a c8 80 e9 ?? 30 88 ?? ?? ?? ?? 40 3d 18 25 00 00 7c ed}  //weight: 2, accuracy: Low
        $x_2_5 = {ff 45 fc 8b 45 fc 6b c0 60 8d 34 18 33 ff 39 3e 75 cd}  //weight: 2, accuracy: High
        $x_2_6 = {a9 00 00 02 00 59 75 e9 a8 20 75 e5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Monkif_J_2147627006_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Monkif.J"
        threat_id = "2147627006"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "uromon.dll" ascii //weight: 10
        $x_10_2 = "163801" ascii //weight: 10
        $x_10_3 = {25 75 7c 00 48 54 54 50 2f 31 2e 30 00}  //weight: 10, accuracy: High
        $x_10_4 = "InternetReadFile" ascii //weight: 10
        $x_1_5 = {c6 45 f4 4c c6 45 f5 6f c6 45 f6 63 c6 45 f7 61 c6 45 f8 6c c6 45 f9 5c c6 45 fa 55 c6 45 fb 49 c6 45 fc 45 c6 45 fd 49}  //weight: 1, accuracy: High
        $x_1_6 = {c6 45 ef 43 c6 45 f0 6f c6 45 f1 6e c6 45 f2 6e c6 45 f3 65 c6 45 f4 63 c6 45 f5 74 c6 45 f6 65 c6 45 f7 64 c6 45 f8 5a c6 45 f9 74 c6 45 fa 61 c6 45 fb 74 c6 45 fc 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Monkif_L_2147628151_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Monkif.L"
        threat_id = "2147628151"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "%s%s.php?%s%c%s" ascii //weight: 2
        $x_2_2 = {76 10 8b 44 24 04 03 c1 80 30 ?? 41 3b 4c 24 08 72 f0}  //weight: 2, accuracy: Low
        $x_2_3 = {03 00 00 74 de 81 3d ?? ?? 00 10 01 03 00 00 74 d2}  //weight: 2, accuracy: Low
        $x_2_4 = {63 c6 45 f5 74 c6 45 f6 65 c6 45 f7 64 c6 45 f8 5a c6 45 f9 74 c6 45 fa 61}  //weight: 2, accuracy: High
        $x_2_5 = {3d fe fb 0f 00 7c dd 5e 81 c4 00 02 00 00 c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Monkif_N_2147628633_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Monkif.N"
        threat_id = "2147628633"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a c8 80 e9 ?? 30 88 ?? ?? ?? ?? 40 3d ?? ?? 00 00 7c ed}  //weight: 2, accuracy: Low
        $x_1_2 = {75 e1 ff 45 fc 8b 45 fc 6b c0 60 8d 34 18 33 ff 39 3e 75 cd}  //weight: 1, accuracy: High
        $x_1_3 = {75 d3 8b 45 0c ff 45 fc 8b 4d fc 6b c9 60 8d 34 01 39 1e 75 b8}  //weight: 1, accuracy: High
        $x_1_4 = {8d 46 fe 83 c4 ?? 3d ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_1_5 = {83 c4 30 46 8d 46 fe 3d ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_1_6 = {58 b9 0f 00 00 00 51 50 cb}  //weight: 1, accuracy: High
        $x_1_7 = "PXocess" ascii //weight: 1
        $x_1_8 = "Pr0cess" ascii //weight: 1
        $x_1_9 = "Pro3ess" ascii //weight: 1
        $x_1_10 = "CBeateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Monkif_O_2147629296_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Monkif.O"
        threat_id = "2147629296"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 3a 70 00 ?? ?? 0f 84 [0-7] 00 00 00 8b 1e}  //weight: 2, accuracy: Low
        $x_2_2 = {81 3a 50 72 ?? ?? 0f 84 [0-7] 00 00 00 8b 1e}  //weight: 2, accuracy: Low
        $x_2_3 = {4b 0f b6 04 19 (2a c2|28 d0) [0-6] 88 04 19 (49|ff c9) 75}  //weight: 2, accuracy: Low
        $x_2_4 = {81 f8 fe fb 0f 00 [0-3] 0f 8c}  //weight: 2, accuracy: Low
        $x_2_5 = {68 3d 00 00 00 [0-16] 68 3f 00 00 00 [0-6] 53 [0-6] 68 ?? ?? ?? 10 68 2f 00 00 00}  //weight: 2, accuracy: Low
        $x_2_6 = {25 73 25 73 2e 70 68 70 [0-3] 25 63 25 73}  //weight: 2, accuracy: Low
        $x_1_7 = {50 72 30 63 65 73 73 33 32 4e 65 78 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {43 42 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Monkif_Q_2147637713_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Monkif.Q"
        threat_id = "2147637713"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3e c6 85 f8 ff ff ff e9 e8}  //weight: 1, accuracy: High
        $x_1_2 = {50 72 6f 33 65 73 73 33 32 46 69 72 73 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 1e 85 db 0f 84 1f 00 00 00 8b 4e 04 83 c6 08 4b 0f b6 04 19 2a c2 81 c2 ?? 00 00 00 88 04 19 49 0f 85 ea ff ff ff eb d7 66 9d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Monkif_S_2147639560_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Monkif.S"
        threat_id = "2147639560"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 3a 5c 72 65 63 6f 76 65 72 79 2e 62 61 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {71 71 25 73 25 73 2e 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 50 52 4f 50 4f 43 4f 4c 53 5c 46 69 6c 74 65 72 5c 74 65 78 74 2f 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 72 70 61 74 65 54 6f 38 6c 68 65 6c 70 33 35 53 6e 61 70 30 68 6f 74 00}  //weight: 1, accuracy: High
        $x_5_5 = {8a c8 80 e9 6b 30 88 ?? ?? ?? 10 40 3d 8a 3c 00 00 7c ed 56 57 53 8d 45 f4 50 68 ?? ?? ?? ?? 68 ?? ?? ?? 10 ff 75 f8 e8}  //weight: 5, accuracy: Low
        $x_5_6 = {55 8b ec 83 ec 1c 8d 45 f4 50 c6 45 f4 6b c6 45 f5 65 c6 45 f6 72 c6 45 f7 6e c6 45 f8 65 c6 45 f9 6c c6 45 fa 33 c6 45 fb 32 c6 45 fc 00 c6 45 e4 43 c6 45 e5 72 c6 45 e6 65 c6 45 e7 61 c6 45 e8 74 c6 45 e9 65 c6 45 ea 4d c6 45 eb 75 c6 45 ec 74 c6 45 ed 65 c6 45 ee 78 c6 45 ef 41 c6 45 f0 00 ff 15 ?? ?? ?? ?? 85 c0 75 04 33 c0 c9 c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Monkif_T_2147639659_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Monkif.T"
        threat_id = "2147639659"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 19 (2a c2|28 d0) [0-6] 88 04 19 (49|ff c9) (75|0f 85)}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 85 f8 ff ff ff e9 [0-6] e8}  //weight: 1, accuracy: Low
        $x_1_3 = {68 e8 ff ff ff ?? ?? ?? [0-6] ff 15 ?? ?? ?? ?? 81 f8 ff ff ff ff [0-6] 0f 84 ?? ?? ?? ?? [0-7] (8d 85 f4 ff|8d)}  //weight: 1, accuracy: Low
        $x_1_4 = {6d 73 79 75 76 2e 64 6c 6c 00 45 78 70 6f 72 74 31 00}  //weight: 1, accuracy: High
        $x_1_5 = {25 63 25 73 25 73 2e 70 68 70 25 63 25 73 25 63 25 73 00 00 70 68 6f 74 6f 2f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Monkif_U_2147640558_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Monkif.U"
        threat_id = "2147640558"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0e 2a c2 2c ?? 42 3b 54 24 10 88 01 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 8a c8 80 e9 ?? 30 88 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 73 79 75 76 2e 64 6c 6c 00 45 78 70 6f 72 74 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Monkif_W_2147649955_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Monkif.W"
        threat_id = "2147649955"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Monkif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4b 0f b6 04 19 (2a c2|28 d0) [0-6] 88 04 19 (49|ff c9) 75}  //weight: 2, accuracy: Low
        $x_2_2 = {48 74 74 33 [0-3] c7 85 ?? ?? ?? ?? 53 65 6e 64}  //weight: 2, accuracy: Low
        $x_1_3 = "Pro3ess32" ascii //weight: 1
        $x_1_4 = "CrpateTo8lhelp35Snap0hot" ascii //weight: 1
        $x_1_5 = "%xxx%fdd%xgg%pjj" ascii //weight: 1
        $x_2_6 = {25 63 25 73 25 63 25 73 [0-5] 70 68 6f 74 6f 2f [0-5] 2e 70 68 70}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

