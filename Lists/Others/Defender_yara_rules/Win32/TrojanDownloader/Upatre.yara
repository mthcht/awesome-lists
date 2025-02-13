rule TrojanDownloader_Win32_Upatre_A_2147682923_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.A"
        threat_id = "2147682923"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 55 00 70 00 64 00 61 00 74 00 65 00 73 00 20 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 41 3c ff 75 ?? 03 c1 0f b7 (48|50) 06 6b (c9|d2) 28 8d 84 (01|02) d0 00 00 00 8b (70|78) 14 03 (70|78) 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_A_2147682923_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.A"
        threat_id = "2147682923"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 55 00 70 00 64 00 61 00 74 00 65 00 73 00 20 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "/wp-content/uploads/2013/" wide //weight: 1
        $x_1_3 = {83 c4 10 56 68 80 00 00 00 6a 03 56 6a 01 68 00 00 00 80 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_D_2147683788_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.D"
        threat_id = "2147683788"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 55 70 64 61 74 65 73 20 64 6f 77 6e 6c 6f 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_5_2 = {ba 00 00 ff ff 55 8b ec 83 ec 10 8b 45 ?? 23 c2 f7 d2 42 03 c2 2b c2 8b 08 80 f9 4d 75 ?? 80 fd 5a 75 ?? 0f b7 48 3c 53 89 45 ?? 8d 44 01 18 b9 09 01 00 00 56 57 41 41 66 39 08}  //weight: 5, accuracy: Low
        $x_5_3 = {ba 01 00 ff ff 8b 45 ?? e8 ?? ?? ?? ?? 03 c2 2b c2 8b 08 80 f9 4d 75 ?? 80 fd 5a 75 ?? 53 e8 ?? ?? ?? ?? 41 56 57 41 66 39 08 75 ?? e8 ?? ?? ?? ?? 33 d2 8b 5d ?? 8b ca 4b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Upatre_D_2147683788_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.D"
        threat_id = "2147683788"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e6 ff 00 00 00 8a 14 06 30 14 39 47 3b 7d 0c 72 c8}  //weight: 1, accuracy: High
        $x_1_2 = "vfs\\soft32.dll" wide //weight: 1
        $x_1_3 = {89 08 c7 40 04 ?? ?? ?? ?? c7 40 08 ?? ?? ?? ?? 8b 56 04 8b 4e 0c 2b 4a 34 81 c1 ?? ?? ?? ?? 74 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_2147684158_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre"
        threat_id = "2147684158"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 05 48 ab 5a bb 08 59 7a 14 4a ad 2b c3 89 07 03 fa 49 75 f6}  //weight: 1, accuracy: High
        $x_1_2 = {40 00 41 5f 41 89 07 51 47 47 58 47 47 6a 05 48 ab 5a bb ?? ?? ?? ?? 4a 04 00 54 b8}  //weight: 1, accuracy: Low
        $x_1_3 = {bb 10 a4 38 22 58 48 ab 8b c6 8b 00 83 c6 04 8b d3 2b c2 ab 49 75 f1 e8 ?? ?? ?? ?? bf ?? ?? ?? ?? 5e 68 10 65 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {bb 54 c1 13 1f 54 41 5f ab 41 51 58 48 ab 51 6a 04 8b c6 8b c8 8b 00 59 03 f1 59 2b c3 ab e2 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_E_2147684205_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.E"
        threat_id = "2147684205"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 fc 8b d8 33 c0 43 8b 0b 40 81 e1 ff 00 00 00 85 c9 75 f2 48 3b 45 ?? 75 12 8b 07 03 45 ?? ff 75 ?? 50 e8 ?? 00 00 00 85 c0 74 0e 83 c7 04 ff 45 f8 8b 45 f8 3b 45 f4 72 c2 8b 45 f8 3b 45 f4 73 1f 8b 4e 24 03 c8 03 c8 8b 45 fc 03 c8 0f b7 01 8b 4e 1c 8d 04 81 8b 4d fc 8b 04 01 03 c1 eb 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_F_2147684245_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.F"
        threat_id = "2147684245"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 00 03 00 00 0f 84 ?? 00 00 00 3d 05 40 02 00 0f 84 ?? 00 00 00 81 fa 06 40 02 00 0f 84 ?? 00 00 00 3d ff 01 02 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 00 03 00 00 0f 84 ?? 00 00 00 0f 84 ?? 00 00 00 3d 05 40 02 00 0f 84 ?? 00 00 00 0f 84 ?? 00 00 00 81 fa 06 40 02 00 0f 84 ?? 00 00 00 0f 84 ?? 00 00 00 3d ?? 01 02 00}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 00 03 00 00 0f 84 ?? 00 00 00 0f 84 ?? 00 00 00 3d fd 01 02 00 90 0f 8e ?? 02 00 00 0f 8e ?? 02 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {05 3d 00 00 00 48 8b 00 03 ?? 6a 1e ?? 83 ?? 02 8b 04 ?? 3d fd 06 02 00}  //weight: 1, accuracy: Low
        $x_1_5 = {05 78 00 00 00 d1 c8 03 ?? 8b 00 03 ?? 6a 1e 5e 83 ee 02 8b 04 30 be ff 06 02 00}  //weight: 1, accuracy: Low
        $x_1_6 = {05 f0 00 00 00 ?? c8 ?? 03 ?? 8b 00 03 ?? 6a 1e ?? 83 ?? 02 8b 04 ?? ?? ff 06 02 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_G_2147684250_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.G"
        threat_id = "2147684250"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4e 24 03 c8 03 c8 8b 45 fc 03 c8 0f b7 01 8b 4e 1c 8d 04 81 8b 4d fc 8b 04 01}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4d d4 8b 7d e4 8b 45 e8 03 f8 8b 75 f4 fc f3 a4 5e 6a 00 68 80 00 00 00 6a 02 6a 00 6a 02 68 00 00 00 40 ff 75 f0 ff 55 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_G_2147684250_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.G"
        threat_id = "2147684250"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 8b d8 53 4b ad 51 8b c8 8b 07 33 c8 88 0f 83 c7 01 59 83 ee 03 83 fb 00}  //weight: 1, accuracy: High
        $x_1_2 = {60 50 8b d8 51 ad 4b 4e 4e 53 8b c8 8b 07 33 c1 4e aa 58 59}  //weight: 1, accuracy: High
        $x_1_3 = {8b d8 53 51 ac 4b 8b c8 8b 07 33 c1 88 07 47 59 83 fb 00}  //weight: 1, accuracy: High
        $x_1_4 = {51 53 8b c8 8b 07 33 c8 4e 88 0f 4e 47 58 4e 59 83 f8 00}  //weight: 1, accuracy: High
        $x_1_5 = {51 53 8b c8 8b 07 33 c8 4e 8b c1 aa 4e 58 4e 59 83 f8 00}  //weight: 1, accuracy: High
        $x_1_6 = {8b d8 53 8b 07 33 06 46 88 07 47 4b}  //weight: 1, accuracy: High
        $x_1_7 = {50 8b d8 ac 33 07 aa 4b 0f 84 ?? ?? ?? ?? 49 75 f2 58 8b c1}  //weight: 1, accuracy: Low
        $x_1_8 = {50 8b d8 8b 17 8b 06 46 33 c2 aa 4b 0f 84 ?? ?? 00 00 49 75 ee 58 8b c1}  //weight: 1, accuracy: Low
        $x_1_9 = {8b d9 ac 8a 0f 32 c8 4a 75 06 58 2b f0 50 8b d0 8b c1 aa 8b cb e2 e9}  //weight: 1, accuracy: High
        $x_1_10 = {8b d0 50 51 8b 07 50 ad 59 33 c1 4a 75 06 59 5a 2b f2 52 51 59 4e 4e aa 4e 49 75 e7}  //weight: 1, accuracy: High
        $x_1_11 = {8b d0 50 51 ad 50 8b 07 59 33 c8 4a 75 06 58 5a 2b f2 52 50 88 0f 59 4e 4e 47 4e 49}  //weight: 1, accuracy: High
        $x_1_12 = {51 8b 0f ad 4e 4e 4e 33 c1 4a 59 75 04 5a 2b f2 52 aa 49 75 eb}  //weight: 1, accuracy: High
        $x_1_13 = {8b d0 50 ad 51 8b c8 4e 4e 8b 07 4e 33 c8 4a 75 08 8b 44 24 04 2b f0 8b d0 8b c1 59 aa 49 75 e3}  //weight: 1, accuracy: High
        $x_1_14 = {33 d2 52 50 92 51 ad 4e 91 4e 4e 33 0f 4a 75 08 8b 44 24 04 8b d0 2b f0 8b c1 aa 59 e2 e7 59}  //weight: 1, accuracy: High
        $x_1_15 = {8b d8 33 c0 50 53 51 33 c9 ac 0b c8 87 f7 ac 4b 33 c1 87 f7 8b cb e3 17 4f aa 59 e2 e9}  //weight: 1, accuracy: High
        $x_1_16 = {51 33 c9 ac 0b c8 87 f7 ac 4b 33 c1 87 f7 8b cb e3 0b 4f aa 59 e2 e9 59 58 5b c3}  //weight: 1, accuracy: High
        $x_1_17 = {50 51 33 c9 ac 56 8b f7 0b c8 ac 4b 8b fe 33 c1 8b cb 5e e3 ?? 4f aa 59 e2}  //weight: 1, accuracy: Low
        $x_1_18 = {8b 55 14 8b 4d 0c ac 33 07 aa 4a 75 06 8b 75 10 8b 55 14 e2 f1}  //weight: 1, accuracy: High
        $x_1_19 = {ac 8b 0f 23 cb 33 c1 88 07 4a 75 06 8b 75 10 8b 55 14 47 59 e2 e4}  //weight: 1, accuracy: High
        $x_1_20 = {ac 4a 23 cb 33 c1 88 07 85 d2 75 06 8b 55 14 8b 75 10 59 47 e2 e7}  //weight: 1, accuracy: High
        $x_1_21 = {8b 4d 0c 4a 51 ad 8b 0f 4e 33 c1 4e 88 07 4e 85 ?? 75 06 8b 55 14 8b 75 10 59 47 e2}  //weight: 1, accuracy: Low
        $x_1_22 = {8b 07 8b d0 ad 32 e2 5a c1 e8 08 4e 4e 4a 52 aa 58 85 c0 75 08 8b 45 10 8b 55 14 8b f0}  //weight: 1, accuracy: High
        $x_1_23 = {8b 75 ce 89 f7 8b 45 e2 bb 04 00 00 00 f6 f3 89 c1 8b 5d f2 ad 31 d8 ab e2 fa ff 65 ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_H_2147684268_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.H"
        threat_id = "2147684268"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ges/html/*xe" wide //weight: 1
        $x_1_2 = "htbkgrnd" wide //weight: 1
        $x_1_3 = {8b 45 b4 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_H_2147684268_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.H"
        threat_id = "2147684268"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a3 04 d9 40 00 66 c7 85 2c ff ff ff 6b 00 8a 8d 34 ff ff ff 88 8d 4d ff ff ff c6 45 a8 65 66 c7 85 2e ff ff ff 65 00 c6 45 ae 45 8a 95 2e ff ff ff 88 95 52 ff ff ff 66 c7 85 3a ff ff ff 32 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 85 4c ff ff ff 47 c6 85 4d ff ff ff 0d c6 85 4e ff ff ff 74 c6 85 4f ff ff ff 46 c6 85 50 ff ff ff 69 c6 85 51 ff ff ff 6c c6 85 52 ff ff ff 70 c6 85 53 ff ff ff 41 c6 85 54 ff ff ff 74 c6 85 55 ff ff ff 74 c6 85 56 ff ff ff 72}  //weight: 1, accuracy: High
        $x_1_3 = {ff ff ff 6b 8a 8d ?? ff ff ff 88 8d ?? ff ff ff c6 45 a8 65 ?? ?? ?? ff ff ff 65 c6 45 ae 45 8a 95 ?? ff ff ff 88 95 ?? ff ff ff ?? ?? ?? ff ff ff 32}  //weight: 1, accuracy: Low
        $x_1_4 = {c6 45 a8 65 8a 95 ?? ff ff ff 88 95 ?? ff ff ff ?? ?? ?? 2e ff ff ff 65 00 c6 45 ae 45 8a 85 ?? ff ff ff 88 85 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_5 = {c6 45 bc 65 8a 95 ?? ff ff ff 88 95 ?? ff ff ff ?? ?? ?? ?? ff ff ff 65 00 c6 45 ?? 45 8a 85 ?? ff ff ff 88 85 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_6 = {c6 45 bc 65 c6 85 79 ff ff ff 65 c6 45 c2 45 c6 85 7e ff ff ff 65 68 ?? ?? 40 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_7 = {c6 45 86 70 c6 45 87 41 c6 45 88 74 c6 45 89 74 c6 45 8a 72 c6 45 8b 69 c6 45 8c 62 c6 45 8d 75 c6 45 8e 74 c6 45 8f 65 c6 45 90 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_I_2147684388_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.I"
        threat_id = "2147684388"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4e 24 03 c8 03 c8 8b 45 fc 03 c8 0f b7 01 8b 4e 1c 8d 04 81 8b 4d fc 8b 04 01}  //weight: 5, accuracy: High
        $x_5_2 = {2b c2 8b 08 fe c9 80 f9 4c 75 f5 fe c5 80 fd 5b 75 ee 53}  //weight: 5, accuracy: High
        $x_1_3 = {51 e8 14 00 00 00 46 47 59 4b 74 07 49 75 f1}  //weight: 1, accuracy: High
        $x_1_4 = {51 e8 12 00 00 00 59 4b 74 07 49 75 f3 5b}  //weight: 1, accuracy: High
        $x_1_5 = {51 8b 06 8b 0f e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 47 4b 8b c3 59}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 06 32 c1 c3}  //weight: 1, accuracy: High
        $x_3_7 = {8b 55 e4 0f b7 42 3c 03 d0 0f b7 4a 06 83 c2 14 0f b7 02}  //weight: 3, accuracy: High
        $x_2_8 = {00 55 70 64 61 74 65 73 20 64 6f 77 6e 6c 6f 61 64 65 72 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Upatre_L_2147684820_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.L"
        threat_id = "2147684820"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 55 70 64 61 74 65 73 20 64 6f 77 6e 6c 6f 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 48 3c 89 45 ?? 81 e1 ff ff 00 00 03 c1 b9 18 00 00 00 03 c1}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 5a 5a 50 00 0f ?? ?? 00 00 00 8b 45 ?? c1 e0 02 89 45 ?? 50 6a 08 ff 75 ?? ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_V_2147686646_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.V"
        threat_id = "2147686646"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 3d 5a 5a 50 00 0f 85 ?? ?? ?? ?? 8b 45 ?? c1 e0 02 89 45 ?? 50 6a 08 ff 75 ?? ff 55 ?? 85 c0 0f 84 ?? ?? ?? ?? 89 45 ?? 8b 45 ?? c1 e0 02 e8 00 00 00 00 59 83 c1 06 eb ?? 52 74 6c 44 65 63 6f 6d 70 72 65 73 73 42 75 66 66 65 72 00 6e 74 64 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_AA_2147686976_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.AA"
        threat_id = "2147686976"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 7c 24 2c 80 ?? 4d 75 ?? 80 ?? 01 5a 0f 84 ?? ?? ?? ?? 8b 44 24 10 8b 14 ?? ?? ?? ?? ?? 33 c0 8b cf 40 c1 e9 02 3b c8 76 ?? 31 ?? ?? 40}  //weight: 10, accuracy: Low
        $x_10_2 = {03 f7 8b 06 33 c2 89 06 42 49 75}  //weight: 10, accuracy: High
        $x_10_3 = {03 f2 8b 06 33 c7 89 06 47 49 75}  //weight: 10, accuracy: High
        $x_8_4 = {8a cc 8b 45 e8 8b 14 88 6a 04 5f 8b 4d 04 c1 e9 02 49 8b 75 00 03 f7 31 16 42 e2 f9}  //weight: 8, accuracy: High
        $x_10_5 = {8b 00 66 3d 4d 5a 0f 84 ?? ?? ?? ?? 8b 45 b4 c1 e0 02 89 45 a8}  //weight: 10, accuracy: Low
        $x_10_6 = {8b 07 66 3d 4d 5a 74 ?? 8b 45 88 8b c8 8b 95 ?? ?? ?? ?? c1 e0 02 03 d0 8b 02}  //weight: 10, accuracy: Low
        $x_10_7 = {80 3b 4d 8b f8 75 12 80 7b 01 5a 75 0c ff 75 fc 53 57 e8}  //weight: 10, accuracy: High
        $x_10_8 = {89 74 24 20 80 ?? 5a 0f 85 ?? ?? ?? ?? 80 ?? 01 5a 0f 85 ?? ?? ?? ?? 80 ?? 02 50 0f 85 ?? ?? ?? ?? 80 ?? 03 00 0f 85 ?? ?? ?? ?? 8b 54 24 28 33 c0 8b 14 ?? ?? ?? ?? ?? 8b ce c1 e9 02 40 3b c8 76 08 31 ?? ?? 40}  //weight: 10, accuracy: Low
        $x_10_9 = {8b 55 e4 0f b7 42 3c 03 d0 0f b7 4a 06 83 c2 14 0f b7 02}  //weight: 10, accuracy: High
        $x_10_10 = {89 45 04 89 45 44 8b 45 00 66 81 38 4d 5a}  //weight: 10, accuracy: High
        $x_8_11 = {89 45 c0 89 45 e0 8b 45 bc 8b 00 66 3d 4d 5a}  //weight: 8, accuracy: High
        $x_3_12 = {00 00 33 c0 39 44 24 0c 76 15 8b 4c 24 08 8a 0c 08 8b 54 24 04 88 0c 10 40 3b 44 24 0c 72 eb}  //weight: 3, accuracy: High
        $x_1_13 = {00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00}  //weight: 1, accuracy: High
        $x_1_14 = {00 74 65 78 74 2f 2a 00}  //weight: 1, accuracy: High
        $x_1_15 = {2e 72 61 72 00}  //weight: 1, accuracy: High
        $x_1_16 = {2e 65 6e 63 00}  //weight: 1, accuracy: High
        $x_1_17 = {2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_18 = {2e 7a 69 70 00}  //weight: 1, accuracy: High
        $x_1_19 = {2e 63 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_20 = {2e 70 64 66 00}  //weight: 1, accuracy: High
        $x_2_21 = {43 3a 5c 54 45 4d 50 5c [0-6] 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_1_22 = {00 00 75 00 70 00 64 00 61 00 74 00 65 00 73 00 20 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_23 = "Conchita Wurst" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_1_*))) or
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*))) or
            ((2 of ($x_8_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Upatre_AF_2147689171_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.AF"
        threat_id = "2147689171"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fc ad ab 33 c0 66 ad ab e2 f7}  //weight: 2, accuracy: High
        $x_2_2 = {5b 83 c3 09 e9 ?? ?? ?? ?? 4c 6f 61 64 4c}  //weight: 2, accuracy: Low
        $x_2_3 = {03 f2 51 8b 06 8b cf 33 c1 89 06 47 59 49 75 f0}  //weight: 2, accuracy: High
        $x_2_4 = {68 02 01 00 00 ff 55 68 8b 07 66 3d 4d 5a 74 31}  //weight: 2, accuracy: High
        $x_2_5 = {8b c2 03 f0 8b 06 33 c7 47 89 06 e2 f3}  //weight: 2, accuracy: High
        $x_1_6 = {8b 00 fe c8 fe c4 66 3d 4c 5b 0f 84}  //weight: 1, accuracy: High
        $x_2_7 = {03 f2 51 57 8b 06 59 33 c1 89 06 03 f2 59 47 e2 f1}  //weight: 2, accuracy: High
        $x_1_8 = {57 ab 33 c0 ab e2 fd 8b 7d ?? 57 ab ab ab ab 8b f8}  //weight: 1, accuracy: Low
        $x_1_9 = {fc ad ab 33 c0 66 ad 66 ab 33 c0 ac 66 ab e2 f1}  //weight: 1, accuracy: High
        $x_1_10 = {b0 25 66 ab b0 75 66 ab b0 00 66 ab}  //weight: 1, accuracy: High
        $x_2_11 = {51 33 c9 fc ad ab 8b c1 fc 66 ad 66 ab 8b c1 fc ac 66 ab 59 e2 ea}  //weight: 2, accuracy: High
        $x_2_12 = {57 ab ab ab ab b8 ?? ?? ?? ?? 57 ab 33 c0 ab e2 fd}  //weight: 2, accuracy: Low
        $x_2_13 = {b8 52 74 6c 44 89 06 56 ff 75 ?? ff 55 ?? 50 b8 21 21 21 21 89 06}  //weight: 2, accuracy: Low
        $x_2_14 = {b0 31 66 ab b0 2f 66 ab 8b c1 04 30 b4 00 66 ab b0 2f 66 ab}  //weight: 2, accuracy: High
        $x_2_15 = {3d 64 64 72 65 e0 f6 67 e3 c1 46 46 46 ad 2d 73 73 3a 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Upatre_AH_2147689437_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.AH"
        threat_id = "2147689437"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 45 00 3d d0 07 00 00 76 ?? 89 45 04 89 45 44 8b 45 00 40 66 81 38 4e 5a}  //weight: 1, accuracy: Low
        $x_1_2 = {68 80 00 00 00 6a 02 50 6a 02 68 00 00 00 40 8b 45 ec b4 04 ff 55 24 8a cc}  //weight: 1, accuracy: High
        $x_1_3 = {f3 a4 5e 51 68 80 00 00 00 6a 02 51 6a 02 68 00 00 00 40 ff 75 54}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_AI_2147689471_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.AI"
        threat_id = "2147689471"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fc ad ab 33 c0 66 ad ab e2 f7}  //weight: 2, accuracy: High
        $x_2_2 = {5b 83 c3 09 e9 ?? ?? ?? ?? 4c 6f 61 64 4c}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 00 fe c8 fe c4 66 3d 4c 5b 0f 84}  //weight: 1, accuracy: High
        $x_1_4 = {ff d1 2b c2 8b 08 02 cd fe c1 66 81 f9 a8 5a 75 f1}  //weight: 1, accuracy: High
        $x_1_5 = {63 25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_AJ_2147689534_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.AJ"
        threat_id = "2147689534"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {89 45 00 05 80 84 1e 00 89 45 fc 05 00 12 7a 00 89 45 58 8b f8 be 00 10 00 00 03 c6 89 45 54}  //weight: 4, accuracy: High
        $x_1_2 = {3a 30 25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e 00 74 65 78 74 2f 2a}  //weight: 1, accuracy: High
        $x_1_3 = {00 25 73 5c 25 73 00 6f 70 65 6e 00 74 65 78 74 2f 2a 00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00 47 45 54 00 46 61 73 74 55 70 64 61 74 65}  //weight: 1, accuracy: High
        $x_1_4 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e 00 74 65 78 74 2f 2a 00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00 47 45 54 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Upatre_AK_2147689641_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.AK"
        threat_id = "2147689641"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c2 14 0f b7 02 8d 54 10 04 6a 28 58 49 03 d0 e2 fc}  //weight: 1, accuracy: High
        $x_1_2 = {8b 75 00 03 f7 8b c2 31 06 42 e2 f7}  //weight: 1, accuracy: High
        $x_1_3 = {66 81 3f 4d 5a 74 ?? 8b ?? ec 8b 55 c4 [0-10] 3c 05 77}  //weight: 1, accuracy: Low
        $x_1_4 = {a5 66 ad ab e2 fa 5b 33 c0 b4 04 50}  //weight: 1, accuracy: High
        $x_1_5 = {8b 4c 03 04 66 81 c9 20 20 [0-4] 81 e9 65 6c 33 32}  //weight: 1, accuracy: Low
        $x_1_6 = {ac 3c 01 74 0f 84 c0 74 02 34 ?? 66 ab 41 84 c0 75 ee}  //weight: 1, accuracy: Low
        $x_1_7 = {57 56 ad 33 c7 5f ab 8b f7 5f 4f 49 75}  //weight: 1, accuracy: High
        $x_1_8 = {6a 34 58 66 ab b0 31 66 ab b0 2f 66 ab 8a c1 04 30 66 ab b0 2f 66 ab}  //weight: 1, accuracy: High
        $x_1_9 = {6a 34 58 66 ab 6a 2f 6a 31 58 66 ab 58 50 66 ab 8a c1 04 2f 40 66 ab}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_A_2147689809_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.gen!A"
        threat_id = "2147689809"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fc ad ab 33 c0 66 ad ab e2 f7}  //weight: 2, accuracy: High
        $x_2_2 = {5b 83 c3 09 e9 ?? ?? ?? ?? 4c 6f 61 64 4c}  //weight: 2, accuracy: Low
        $x_1_3 = {00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 74 65 78 74 2f 2a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Upatre_AL_2147689907_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.AL"
        threat_id = "2147689907"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 06 40 40 46 3d 66 64 72 65 e0 f4}  //weight: 1, accuracy: High
        $x_1_2 = {ad 33 c3 43 ab e2 f9}  //weight: 1, accuracy: High
        $x_1_3 = {5b 80 e7 f0 6a 05 8d 7d 14 32 db}  //weight: 1, accuracy: High
        $x_1_4 = {66 ad 66 85 c0 74 f9 8b fe eb 16 3c 00 75 b2 04 30 66 ab}  //weight: 1, accuracy: High
        $x_1_5 = {61 37 25 73 25 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {8b 06 40 ba 67 64 72 65 40 4a 46 3b c2 e0 f1}  //weight: 1, accuracy: High
        $x_1_7 = {68 38 25 73 25 73 00}  //weight: 1, accuracy: High
        $x_1_8 = {66 ad 03 c3 ab 33 c0 e2 f7}  //weight: 1, accuracy: High
        $x_1_9 = {8b fe ad 33 45 ?? ff 45 ?? 89 07}  //weight: 1, accuracy: Low
        $x_1_10 = {ab 49 75 fc 57 b9 ?? ?? ?? ?? 41 89 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_AM_2147690284_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.AM"
        threat_id = "2147690284"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e 00 74 65 78 74 2f 2a 00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00 47 45 54 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30}  //weight: 1, accuracy: High
        $x_1_2 = {57 ab 33 c0 ab e2 fd 8b 7d ?? 57 ab ab ab ab 8b f8}  //weight: 1, accuracy: Low
        $x_1_3 = {03 f2 51 57 8b 06 59 33 c1 89 06 03 f2 59 47 e2 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_AN_2147690347_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.AN"
        threat_id = "2147690347"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 2d 66 ab b0 53 66 ab b0 50 66 ab 58 04 30 66 ab 33 c0 b0 2f 66 ab}  //weight: 1, accuracy: High
        $x_1_2 = {b0 53 66 ab b0 45 66 ab b0 52 66 ab 83 ee 07 66 ad 66 85 c0 74 12}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_AO_2147690667_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.AO"
        threat_id = "2147690667"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 ab 33 c0 ab e2 fd 8b 7d ?? 57 ab ab ab ab 8b f8}  //weight: 1, accuracy: Low
        $x_2_2 = {03 f2 51 57 8b 06 59 33 c1 89 06 03 f2 59 47 e2 f1}  //weight: 2, accuracy: High
        $x_2_3 = {43 3a 5c 54 45 4d 50 5c [0-6] 2e 65 78 65}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_AQ_2147690991_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.AQ"
        threat_id = "2147690991"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e 00 74 65 78 74 2f 2a 00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00 47 45 54 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30}  //weight: 2, accuracy: High
        $x_1_2 = {57 ab 33 c0 ab e2 fd 8b 7d ?? 57 ab ab ab ab 8b f8}  //weight: 1, accuracy: Low
        $x_1_3 = {03 f2 51 57 8b 06 59 33 c1 89 06 03 f2 59 47 e2 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Upatre_AR_2147691039_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.AR"
        threat_id = "2147691039"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e 00 74 65 78 74 2f 2a 00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00 47 45 54 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30}  //weight: 1, accuracy: High
        $x_1_2 = {6a 25 58 66 ab b0 75 66 ab b0 00 66 ab}  //weight: 1, accuracy: High
        $x_1_3 = {33 c0 66 ad 03 c3 ab e2 f7 91 6a 04 68 00 10 00 00 68 60 ee a6 00 50 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_C_2147691549_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.gen!C"
        threat_id = "2147691549"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {85 c0 74 e7 58 3d e8 03 00 00 72 05 e9}  //weight: 5, accuracy: High
        $x_5_2 = {be 1e 00 00 00 ff 75 00 ff ?? ?? ?? ?? ?? 85 c0 75 10 6a 01 68 e8 03 00 00 ff ?? ?? ?? ?? ?? 4e 75}  //weight: 5, accuracy: Low
        $x_5_3 = {b9 04 00 00 00 ab e2 fd 57 b9 44 00 00 00 89 0f ab e2 fd}  //weight: 5, accuracy: High
        $x_1_4 = {00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 74 65 78 74 2f 2a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_AS_2147691619_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.AS"
        threat_id = "2147691619"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 9c 8b ec e8 00 00 00 00 5b 81 c4 7c ff ff ff 80 e7 f0 6a 06 32 db 53 8d 7d 14 5e 59 33 c0 66 ad 03 c3 ab 49 75 f6}  //weight: 1, accuracy: High
        $x_1_2 = {b8 04 00 00 00 50 68 00 10 00 00 68 70 15 a7 00 6a 00 ff 93 08 11 00 00 85 c0}  //weight: 1, accuracy: High
        $x_1_3 = {8b c7 2b 45 00 3d 88 13 00 00 77 73 8b 4d ec 3b c9 75 bc 8b c8 8b 7d b4 8b 07 85 c0 75 b1 8b 75 00 8b 06 46 3d 64 64 72 65 e0 f6 67 e3 a1 46 46 46 ad 2d 73 73 3a 20 75 96}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_D_2147691671_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.gen!D"
        threat_id = "2147691671"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {85 c0 74 e7 58 [0-3] 3d 00 04 00 00 76 05 e9}  //weight: 5, accuracy: Low
        $x_5_2 = {be 20 00 00 00 ff 75 00 ff ?? ?? ?? ?? ?? 85 c0 75 0f 50 68 4c 04 00 00 ff ?? ?? ?? ?? ?? 4e 75}  //weight: 5, accuracy: Low
        $x_5_3 = {b1 04 ab 49 75 fc 57 b9 44 00 00 00 89 0f ab 49 75 fc}  //weight: 5, accuracy: High
        $x_1_4 = {00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 74 65 78 74 2f 2a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_AU_2147691708_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.AU"
        threat_id = "2147691708"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6a 01 58 48 ab e2 fd}  //weight: 5, accuracy: High
        $x_5_2 = {58 40 40 3d 28 04 00 00 72 05 e9}  //weight: 5, accuracy: High
        $x_5_3 = {51 33 c9 fc ad ab 8b c1 fc 66 ad 66 ab 8b c1 fc ac 66 ab 59 e2 ea}  //weight: 5, accuracy: High
        $x_1_4 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e}  //weight: 1, accuracy: High
        $x_1_5 = "checkip.dyndns.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_AV_2147691721_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.AV"
        threat_id = "2147691721"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e}  //weight: 1, accuracy: High
        $x_1_2 = "checkip.dyndns.org" ascii //weight: 1
        $x_5_3 = {be 20 00 00 00 ff 75 00 ff ?? ?? ?? ?? ?? 85 c0 75 0f 50 68 4c 04 00 00 ff ?? ?? ?? ?? ?? 4e 75}  //weight: 5, accuracy: Low
        $x_5_4 = {b0 53 66 ab b0 45 66 ab b0 52 66 ab}  //weight: 5, accuracy: High
        $x_5_5 = {ff 04 8a 66 b8 02 29 ff 55 28}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_AW_2147691755_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.AW"
        threat_id = "2147691755"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 c1 89 06 03 f2 59 47}  //weight: 5, accuracy: High
        $x_1_2 = {00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 74 65 78 74 2f 2a 00}  //weight: 1, accuracy: High
        $x_1_4 = "RtlDecompressBuffer" ascii //weight: 1
        $x_1_5 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e}  //weight: 1, accuracy: High
        $x_1_6 = "checkip.dyndns.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_AX_2147692367_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.AX"
        threat_id = "2147692367"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 06 46 3d 64 64 72 65 e0 f6}  //weight: 1, accuracy: High
        $x_1_2 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e}  //weight: 1, accuracy: High
        $x_1_3 = {ad ab 33 c0 66 ad 66 ab 33 c0 ac 66 ab e2 f1}  //weight: 1, accuracy: High
        $x_1_4 = {50 b0 2d 66 ab b0 53 66 ab b0 50 66 ab 58 04 2f fe c0 66 ab}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_BC_2147693872_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.BC"
        threat_id = "2147693872"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 ad 03 c3 ab 33 c0 e2 f7 b8 04 00 00 00 6a 04 68 00 10 00 00 68 00 00 aa 00 51 ff 93 28 11 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {ac 3c 39 77 0c 3c 2e 72 08 fe c0 04 13 66 ab e2 ef}  //weight: 2, accuracy: High
        $x_2_3 = {53 8b 5c 24 08 33 c0 c1 c0 07 32 03 43 80 3b 00 75 f5 5b}  //weight: 2, accuracy: High
        $x_2_4 = {5b 83 c3 09 e9 ?? ?? ?? ?? 4c 6f 61 64 4c}  //weight: 2, accuracy: Low
        $x_2_5 = {51 33 c9 fc ad ab 8b c1 fc 66 ad 66 ab 8b c1 fc ac 66 ab 59 e2 ea}  //weight: 2, accuracy: High
        $x_2_6 = {b0 25 66 ab b0 75 66 ab b0 00 66 ab}  //weight: 2, accuracy: High
        $x_2_7 = {05 80 84 1e 00 89 45 ?? 05 80 8d 5b 00 89 45 ?? b9 00 10 00 00}  //weight: 2, accuracy: Low
        $x_2_8 = {66 ad 66 85 c0 74 f9 83 c4 0c 8b fe eb 1e 3c 00 75 b2 fe c0 04 2e fe c0 66 ab 8b 45 cc 33 c9 8b f0 41 eb 85}  //weight: 2, accuracy: High
        $x_2_9 = {04 31 50 b0 2d 66 ab b0 53 66 ab b0 50 66 ab 58 48 66 ab}  //weight: 2, accuracy: High
        $x_1_10 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e}  //weight: 1, accuracy: High
        $x_1_11 = {00 74 65 78 74 2f 2a 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00}  //weight: 1, accuracy: High
        $x_1_13 = "checkip.dyndns.org" ascii //weight: 1
        $x_1_14 = "rtldecompressbuffer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Upatre_BD_2147694088_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.BD"
        threat_id = "2147694088"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 5b 83 c3 09 e9 ?? ?? 00 00 4c 6f 61 64 4c 69 62 72 61 72 79 41}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 04 68 00 10 00 00 68 00 00 a8 00 6a 00 ff 55 40}  //weight: 1, accuracy: High
        $x_1_3 = {b0 53 66 ab b0 45 66 ab b0 52 66 ab}  //weight: 1, accuracy: High
        $x_1_4 = {b8 53 00 45 00 ab b0 52 66 ab}  //weight: 1, accuracy: High
        $x_1_5 = {05 80 84 1e 00 89 45 ?? 05 80 8d 5b 00 89 45 ?? b9 00 10 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_BE_2147694331_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.BE"
        threat_id = "2147694331"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 ad 66 85 c0 74 f9 83 c4 0c 8b fe eb 1e 3c 00 75 b2 fe c0 04 2e fe c0 66 ab 8b 45 cc 33 c9 8b f0 41 eb 85}  //weight: 1, accuracy: High
        $x_1_2 = {b9 bb 01 00 00 85 c0 75 05 b9 50 00 00 00 51 8b 45 ec ff 55 24 8a cc ff 55 20 50 ff 75 3c ff 93 44 11 00 00 59 85 c0 e1 cd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_BG_2147695000_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.BG"
        threat_id = "2147695000"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c6 04 8b d7 8b 06 4f 33 c2 [0-1] 89 06 49 75}  //weight: 1, accuracy: Low
        $x_1_2 = {ac 3c 2e 72 09 3c 39 77 05 04 14 aa e2 f2}  //weight: 1, accuracy: High
        $x_1_3 = {b8 30 75 00 00 89 06 6a 04 56 6a 06 ff 75 ?? ff 55}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 12 ab ab 59 ab 41 ab 41 b8 46 00 00 00 57 48 48 ab 33 c0 ab e2 fd}  //weight: 1, accuracy: High
        $x_1_5 = {fc f3 ab b8 46 00 00 00 59 57 48 48 ab 33 c0 ab e2 fd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_BJ_2147695292_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.BJ"
        threat_id = "2147695292"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {50 8b c6 83 c0 24 8b 00 59 03 c8 03 4d f8 33 c0 66 8b 01 8b 4e 1c 8d 04 81 8b 4d f8 8b 04 01 03 c1 eb 02}  //weight: 8, accuracy: High
        $x_8_2 = {69 63 61 6e 68 61 7a 69 70 2e 63 6f 6d 00 2f 00 31 30 34 2e 33 36 2e 32 33 32 2e 32 31 39}  //weight: 8, accuracy: High
        $x_2_3 = {2f 73 6f 6b 61 31 31 2e 70 6e 67 00 33 38 2e 37 35 2e 33 38 2e 31 38 36}  //weight: 2, accuracy: High
        $x_2_4 = {31 38 38 2e 32 35 35 2e 32 34 31 2e 35 39 00 2f 73 6f 6b 61 31 31 2e 70 6e 67 00 53 4b 41 31 31}  //weight: 2, accuracy: High
        $x_2_5 = {32 34 2e 31 35 39 2e 31 35 33 2e 31 35 33 00 2f 73 6f 6b 61 31 31 2e 70 6e 67}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_BL_2147695348_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.BL"
        threat_id = "2147695348"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 04 00 00 00 6a 04 68 00 10 00 00 68 00 00 aa 00 51 ff 93 28 11 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {b9 80 84 1e 00 89 45 00 03 c1 81 c1 e0 06 5a 00 89 45 fc 03 c1}  //weight: 1, accuracy: High
        $x_1_3 = {b0 54 fe c8 66 ab b0 44 fe c0 66 ab b0 52 66 ab}  //weight: 1, accuracy: High
        $x_1_4 = {b0 54 48 66 ab b0 50 66 ab 58 04 30 66 ab}  //weight: 1, accuracy: High
        $x_1_5 = {ad ab 8b c2 66 ad 66 ab 8b c2 ac 66 ab 49 75 f0}  //weight: 1, accuracy: High
        $x_1_6 = {b0 31 66 ab b0 2f 66 ab 8a c1 04 30 66 ab b0 2f 66 ab}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_BL_2147695348_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.BL"
        threat_id = "2147695348"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 04 68 00 10 00 00 68 f8 ff a7 00 6a 00 ff 55 40}  //weight: 2, accuracy: High
        $x_2_2 = {05 80 84 1e 00 89 45 b8 05 80 8d 5b 00 89 45 f4 5a 03 c2}  //weight: 2, accuracy: High
        $x_2_3 = {b8 52 00 45 00 40 ab b0 52 66 ab}  //weight: 2, accuracy: High
        $x_2_4 = {b8 54 00 45 00 48 ab b0 52 66 ab}  //weight: 2, accuracy: High
        $x_2_5 = {b0 2e 48 66 ab b0 53 6a 50 66 ab 58 66 ab 58 48 66 ab}  //weight: 2, accuracy: High
        $x_1_6 = {00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 74 65 78 74 2f 2a 00}  //weight: 1, accuracy: High
        $x_1_8 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Upatre_BM_2147695383_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.BM"
        threat_id = "2147695383"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 3c 39 77 0c 3c 2e 72 08 fe c0 04 13 66 ab e2 ef}  //weight: 1, accuracy: High
        $x_1_2 = {33 c1 ab ff 45 ?? ff 45 ?? 59 49 75 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c8 fe c1 fe c1 57 fe c1 fe c1 fc ab 49 75 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_BN_2147695455_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.BN"
        threat_id = "2147695455"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 54 6a 50 48 66 ab 58 66 ab 58 48 66 ab}  //weight: 1, accuracy: High
        $x_1_2 = {b0 2f aa 33 c0 aa b8 c8 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 04 68 00 10 00 00 68 e4 dc a7 00 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_BN_2147695455_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.BN"
        threat_id = "2147695455"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 03 f8 58 ff d7 66 c7 01 49 36 c6 41 02 34 83 c1 03 8b f2 81 e6 00 0e 00 00 81 fe 00 04 00 00 75 0d 5f b2 6f 5e 88 11 c6 41 01 00 5b 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {40 00 40 e2 fd ff d0 04 00 8b 0d}  //weight: 1, accuracy: Low
        $x_1_3 = {40 00 92 b9 c8 00 00 00 6a 10 2b c2 23 c1 e2 fa 59 58 85 c0 0f 85 a5 fc ff ff 04 00 ff 35}  //weight: 1, accuracy: Low
        $x_1_4 = {40 00 68 98 00 00 00 8b d0 59 6a 12 2b c2 23 c1 e2 fa 59 58 49 49 75 c3 04 00 ff 35}  //weight: 1, accuracy: Low
        $x_1_5 = {55 8b ec 33 c0 4e 55 40 40 40 4e 40 5f a5 49 75 fc e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_BO_2147696033_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.BO"
        threat_id = "2147696033"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 b0 26 48 66 ab b0 74 40 66 ab 33 c0 66 ab}  //weight: 1, accuracy: High
        $x_1_2 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e}  //weight: 1, accuracy: High
        $x_1_3 = {00 74 65 78 74 2f 2a 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00}  //weight: 1, accuracy: High
        $x_1_5 = {48 ab b0 52 66 ab 07 00 (?? ?? b8 54 00|68 55 00 45 00)}  //weight: 1, accuracy: Low
        $x_1_6 = {66 b8 34 00 66 ab b0 31 66 ab b0 2f 66 ab 8b c1 04 30 b4 00 66 ab b0 2f 66 ab ff 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_BT_2147696848_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.BT"
        threat_id = "2147696848"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 ec 50 6a 6b ff 75 08 ff 15 ?? ?? 40 00 89 45 cc 6a 64 68 ?? ?? 40 00 6a 6c ff 75 08 ff 15}  //weight: 2, accuracy: Low
        $x_1_2 = {5f 40 8b 06 83 c6 04 89 07 47 47 47 47 e2 f3 e8 ?? 01 00 00 e9 ?? 05 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {40 00 6a 06 ff 75 08 6a 1f 6a 64 68 9f 01 00 00 68 90 01 00 00 68 00 00 00 40 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Upatre_BU_2147696925_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.BU"
        threat_id = "2147696925"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 00 63 61 74 73 05 04 00 00 00 c7 00 72 76 2e 64 05 04 00 00 00 c7 00 6c 6c 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {81 c3 02 5e d9 ff 81 c7 ad 0b 40 00 55 5a 66 81 fa 00 ff 0f 86 89 01 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {83 e9 01 34 f1 c0 c0 05 2c 05 8a da fe cb 80 e3 01 32 c3 56}  //weight: 1, accuracy: High
        $x_1_4 = {b9 00 62 00 00 66 85 d2 f7 d2 80 c9 db 8b 4d e0 83 e9 01 89 4d e0 85 c0 76 a0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Upatre_BV_2147696975_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.BV"
        threat_id = "2147696975"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 15 a4 39 60 00 8b c1 25 ff 0f 00 00 66 8b 84 42 84 00 00 00 0f b7 c0 8b d1 c1 ea 05 33 d0 f7 c2 80 7f 00 00 75 0e 83 e0 7f 74 09 b8 01 00 00 00 5d}  //weight: 1, accuracy: High
        $x_1_2 = {48 4f 4c 59 20 53 48 49 54 20 4d 59 0a 47 41 52 44 45 4e 27 53 20 4f 4e 20 46 49 52 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_BW_2147697102_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.BW"
        threat_id = "2147697102"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 b0 26 48 66 ab b0 74 40 66 ab 33 c0 66 ab}  //weight: 1, accuracy: High
        $x_1_2 = {fc ad ab 33 c0 66 ad ab e2 f7}  //weight: 1, accuracy: High
        $x_1_3 = {3d 64 64 72 65 e0 f6 67 e3 c1 46 46 46 ad 2d 73 73 3a 20}  //weight: 1, accuracy: High
        $x_1_4 = {25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e}  //weight: 1, accuracy: High
        $x_1_5 = {00 74 65 78 74 2f 2a 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_BX_2147697212_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.BX"
        threat_id = "2147697212"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 51 8b 0f 33 c1 aa 59 4b 75 04 5b 2b f3 53 49 75 ee}  //weight: 1, accuracy: High
        $x_1_2 = {ff 55 f8 59 58 05 ?? 04 00 00 68 00 01 00 00 50 6a 00 ff 55 f0}  //weight: 1, accuracy: Low
        $x_1_3 = {81 bd 50 ff ff ff 00 60 00 00 0f 85 9b 01 00 00 56 8b 4e 3c 8b 44 0e 28}  //weight: 1, accuracy: High
        $x_1_4 = {c6 00 68 40 89 08 c6 40 04 c3 8b 85 4c ff ff ff 50 89 85 14 ff ff ff ff b5 6c ff ff ff ff 55 c4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_BY_2147697343_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.BY"
        threat_id = "2147697343"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 06 46 3d 64 64 72 65 e0 f6}  //weight: 1, accuracy: High
        $x_1_2 = {ac 40 48 48 74 0c 40 66 ab 83 c1 01 84 c0 75 f0}  //weight: 1, accuracy: High
        $x_1_3 = {6a 2f 6a 2f 6a 31 58 66 ab 58 66 ab}  //weight: 1, accuracy: High
        $x_1_4 = {53 ad 33 c3 ab 5b 4b 49 75 f6}  //weight: 1, accuracy: High
        $x_1_5 = {ab 33 c0 ab e2 fd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_F_2147705501_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.gen!F"
        threat_id = "2147705501"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 ff 55 6c 85 c0 75 0d 6a 01 68 e8 03 00 00 ff 55 50 4e 75 eb}  //weight: 1, accuracy: High
        $x_1_2 = {ff 55 78 33 f6 56 56 56 6a 00 6a 0a b9 06 00 00 00 ff 55 78 50 ff 55 3c 85 c0 74 dd}  //weight: 1, accuracy: High
        $x_1_3 = {ff 55 78 8a cc 51 b9 06 00 00 00 ff 55 78 50 ff 75 10 ff 55 38 59 85 c0 e1 9c}  //weight: 1, accuracy: High
        $x_1_4 = {85 c0 e1 f2 0f 84 46 ff ff ff b8 00 09 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 56 ad 33 c7 5f ab 8b f7 5f 4f 49 75 f2}  //weight: 1, accuracy: High
        $x_1_6 = {66 3d 4c 5b 74 38 8b 45 e4 8b c8 8b 55 c4 c1 e0 02 03 d0 8b 02 83 f8 05 0f 87 1b 01 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {89 02 51 68 04 29 00 00 b9 0a 00 00 00 ff 55 78 6a 01 68 d0 07 00 00 ff 55 50 e9 c3 fc ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_CC_2147706000_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.CC"
        threat_id = "2147706000"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 55 f8 59 58 05 ?? 04 00 00 68 00 01 00 00 50 6a 00 ff 55 f0}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 00 68 40 89 08 c6 40 04 c3 8b 85 4c ff ff ff 50 89 85 14 ff ff ff ff b5 6c ff ff ff ff 55 c4}  //weight: 1, accuracy: High
        $x_1_3 = {81 bd 50 ff ff ff 00 60 00 00 0f 85 9b 01 00 00 56 8b 4e 3c 8b 44 0e 28}  //weight: 1, accuracy: High
        $x_1_4 = {51 8b 0f ac 33 c1 aa 59 4b 75 04 5b 2b f3 53 49 75 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_CF_2147706183_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.CF"
        threat_id = "2147706183"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 1d bc 70 40 00 b9 7f 96 98 00 e8 00 40 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {ff d0 6a 0a ff 35 e4 70 40 00 6a 00 ff 35 44 70 40 00 e8 0c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 00 01 00 00 68 00 01 00 00 68 80 00 00 00 68 90 00 00 00 68 00 00 cf 00 68 00 70 40 00 68 2b 70 40 00 6a 00 ff 15 e4 80 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_CL_2147706764_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.CL"
        threat_id = "2147706764"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d1 85 c0 74 65 31 c0 50 ff 35 ?? ?? 40 00 50 6a 00 6a 4d 68 15 01 00 00 6a 31 6a 41 68 00 00 cf 00}  //weight: 1, accuracy: Low
        $x_1_2 = {56 57 83 7d 0c 01 74 0e 83 7d 0c 05 74 15 83 7d 0c 07 74 13 eb 15 b8}  //weight: 1, accuracy: High
        $x_1_3 = {e8 00 00 00 00 5b 8b b3 ?? ?? 00 00 56 03 76 3c 66 a9 ?? ?? 57 57 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_CO_2147706847_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.CO"
        threat_id = "2147706847"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 00 68 40 89 08 c6 40 04 c3 8b 85 ?? ?? ff ff 50 89 85 ?? ?? ff ff ff b5 ?? ?? ff ff ff 55 bc}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 07 51 8b c8 33 0e 40 40 46 40 40 88 0f 59 47 4b 75 04 5b 2b f3 53 e2 e7}  //weight: 1, accuracy: High
        $x_1_3 = {66 ad 52 03 d0 3b fa 72 04 41 5a eb f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_CQ_2147706857_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.CQ"
        threat_id = "2147706857"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 39 68 01 01 00 00 6a 1d 6a 2d 68 00 00 cf 00 68 00 30 40 00 68 2b 30 40 00 6a 00 b9 a3 63 98 00 e8 ?? ?? ?? ?? 51 c3 85 c0 74 23}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 39 68 01 01 00 00 6a 1d 6a 2d 68 00 00 cf 00 68 00 30 40 00 68 2b 30 40 00 6a 00 b9 69 88 5b 00 e8 ?? ?? ?? ?? 51 c3 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_F_2147706955_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.gen.F!!Upatre.gen!F"
        threat_id = "2147706955"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Upatre: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "F: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 07 51 8b c8 33 0e 40 40 46 40 40 88 0f 59 47 4b 75 04 5b 2b f3 53 e2 e7}  //weight: 1, accuracy: High
        $x_1_2 = {67 e3 03 ff 55 e8 8b 55 14 8b 4a 04 ff 55 e8 55 59 ff d0}  //weight: 1, accuracy: High
        $x_1_3 = {89 68 03 6a 09 59 ff 75 08 58 55 bd ?? ?? ?? ?? 50 8b 45 10}  //weight: 1, accuracy: Low
        $x_1_4 = {67 e3 03 ff 55 e8 8b 55 14 8b 72 10 8b 7a 14 58 33 c9 ff 32 8b 6a 08 c3}  //weight: 1, accuracy: High
        $x_1_5 = {6a 2e 8b 75 d4 59 ac 3a c1 72 0a 3c 39 77 06 83 c0 14 aa e2 f1}  //weight: 1, accuracy: High
        $x_1_6 = {89 29 8b 4d 7c 8b 41 08 8b c8 05 ?? ?? ?? ?? 50 81 c1 ?? ?? ?? ?? 33 c0 89 29 50 50 ff 55 44 fc}  //weight: 1, accuracy: Low
        $x_1_7 = {57 ff 55 6c 85 c0 75 0d 6a 01 68 e8 03 00 00 ff 55 50 4e 75 eb}  //weight: 1, accuracy: High
        $x_1_8 = {ff 55 78 33 f6 56 56 56 6a 00 6a 0a b9 06 00 00 00 ff 55 78 50 ff 55 3c 85 c0 74 dd}  //weight: 1, accuracy: High
        $x_1_9 = {ff 55 78 8a cc 51 b9 06 00 00 00 ff 55 78 50 ff 75 10 ff 55 38 59 85 c0 e1 9c}  //weight: 1, accuracy: High
        $x_1_10 = {85 c0 e1 f2 0f 84 46 ff ff ff b8 00 09 3d 00}  //weight: 1, accuracy: High
        $x_1_11 = {57 56 ad 33 c7 5f ab 8b f7 5f 4f 49 75 f2}  //weight: 1, accuracy: High
        $x_1_12 = {66 3d 4c 5b 74 38 8b 45 e4 8b c8 8b 55 c4 c1 e0 02 03 d0 8b 02 83 f8 05 0f 87 1b 01 00 00}  //weight: 1, accuracy: High
        $x_1_13 = {89 02 51 68 04 29 00 00 b9 0a 00 00 00 ff 55 78 6a 01 68 d0 07 00 00 ff 55 50 e9 c3 fc ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_CM_2147707080_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.CM"
        threat_id = "2147707080"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 16 8d 55 9c [0-24] eb d9 8b ?? 9c [0-12] ff 55 9c c7 45 c8 00 00 00 00 8b 4d fc 51 e8 ?? ?? ff ff 5f 5e 5b 8b e5 5d c2 04 00 55 8b ec a1 ?? ?? 40 00 5d}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 55 9c 52 ff 15 ?? ?? 40 00 6a 00 6a 00 [0-8] ff 15 ?? ?? 40 00 eb (c0|2d|d7) 59 50 ff 65 9c [0-127] 55 8b ec a1 ?? ?? 40 00 5d}  //weight: 1, accuracy: Low
        $x_1_3 = {ad 51 8b cb 2b c1 89 07 8b ca 03 f9 59 49 75 f0 [0-7] 68 [0-2] 00 00 40 48 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Upatre_CP_2147707120_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.CP"
        threat_id = "2147707120"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ad 2b c3 89 07 03 fa 49 75 f6}  //weight: 1, accuracy: High
        $x_1_2 = {43 00 57 00 61 00 73 00 74 00 61 00 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_S_2147741121_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.S!MTB"
        threat_id = "2147741121"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kilimanmen" wide //weight: 1
        $x_1_2 = "Horapplist" wide //weight: 1
        $x_1_3 = "Hokeuj" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_LQ_2147753640_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.LQ!MTB"
        threat_id = "2147753640"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Apple Update Service" wide //weight: 1
        $x_1_2 = "PowerShell.exe -nop -c" wide //weight: 1
        $x_1_3 = "\\Application Data\\contask.exe" wide //weight: 1
        $x_1_4 = "\\Application Data\\conime.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_DEA_2147761345_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.DEA!MTB"
        threat_id = "2147761345"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ed 8b c7 99 8b d9 2b d8 1b ea 2b de 1b 2d ?? ?? ?? ?? b8 9d ff ff ff 2b c7 89 35 ?? ?? ?? ?? 8b f3 2b c6 8b dd 8b 2d ?? ?? ?? ?? 03 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_DEB_2147762003_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.DEB!MTB"
        threat_id = "2147762003"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 16 8a c1 b1 56 f6 e9 02 c2 83 ee 04 81 fe ?? ?? ?? ?? 8a c8 7f e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Upatre_PAEE_2147913611_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upatre.PAEE!MTB"
        threat_id = "2147913611"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d0 83 e3 27 83 f3 c2 31 db 83 d3 53 f8 83 d8 01}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 68 e8 03 00 00 6a ff ff 15 ?? ?? ?? ?? 83 d1 7a 31 3d ?? ?? ?? ?? 11 cb 83 0d ?? ?? ?? ?? 25 ff 0c 24 75 da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

