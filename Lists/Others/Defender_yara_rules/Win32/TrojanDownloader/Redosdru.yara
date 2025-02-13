rule TrojanDownloader_Win32_Redosdru_C_2147695433_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Redosdru.C"
        threat_id = "2147695433"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b c6 44 24 ?? 6f c6 44 24 ?? 74 c6 44 24 ?? 68 c6 44 24 ?? 65 c6 44 24 ?? 72 c6 44 24 ?? 35}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 80 04 06 ?? ff d7 8b 44 24 0c 8a 14 06 80 f2 ?? 88 14 06 46 3b f3 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 44 24 1b 4e c6 44 24 1d 4c c6 44 24 1e 33 c6 44 24 1f 32 c6 44 24 20 2e c6 44 24 21 64 c6 44 24 24 00 c6 44 24 0d 73 c6 44 24 0e 74 c6 44 24 0f 72 c6 44 24 11 65 c6 44 24 12 6e c6 44 24 13 41}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 e0 4d c6 45 e1 6f c6 45 e2 7a 88 55 e3 88 45 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Redosdru_D_2147709446_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Redosdru.D!bit"
        threat_id = "2147709446"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 17 8b 45 fc 80 04 08 7a 03 c1 8b 45 fc 80 34 08 59 03 c1 41 3b ce 7c e9}  //weight: 2, accuracy: High
        $x_2_2 = {8a 14 32 88 10 8b 55 fc 88 19 8b 4d 0c 0f b6 00 03 ca 0f b6 d3 03 c2 8b df 99 f7 fb 8a 04 32 30 01 ff 45 fc 8b 45 fc 3b 45 10 72}  //weight: 2, accuracy: High
        $x_1_3 = {c6 45 f4 4b [0-8] c6 45 f5 6f c6 45 f6 74 c6 45 f7 68 c6 45 f8 65 c6 45 f9 72 c6 45 fa 35 c6 45 fb 39 c6 45 fc 39}  //weight: 1, accuracy: Low
        $x_1_4 = {c6 45 e8 43 c6 45 e9 3a c6 45 ea 5c c6 45 eb 50 c6 45 ec 72 c6 45 ed 6f c6 45 ee 67 c6 45 ef 72 c6 45 f0 61 c6 45 f1 6d c6 45 f2 20 c6 45 f3 46 c6 45 f4 69 c6 45 f5 6c c6 45 f6 65 c6 45 f7 73 c6 45 f8 5c}  //weight: 1, accuracy: High
        $x_1_5 = {ff ff 4d c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 7a c6 85 ?? ?? ff ff 69 c6 85 ?? ?? ff ff 6c c6 85 ?? ?? ff ff 6c c6 85 ?? ?? ff ff 61 c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 34 c6 85 ?? ?? ff ff 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Redosdru_F_2147712299_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Redosdru.F!bit"
        threat_id = "2147712299"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 02 8a 1c 2f 32 da 8b 54 24 1c 88 1c 2f 47 3b fa 72 90}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 20 4d c6 44 24 21 6f c6 44 24 22 7a 88 54 24 23 88 4c 24 26 c6 44 24 27 2f c6 44 24 28 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Redosdru_F_2147712299_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Redosdru.F!bit"
        threat_id = "2147712299"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 08 32 ca 02 ca 88 08 40 4e}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 02 8a 1c 2f 32 da 8b 54 24 1c 88 1c 2f 47 3b fa 72 90}  //weight: 1, accuracy: High
        $x_1_3 = "C:\\Program Files\\Cacrk\\Cacrk.dll" ascii //weight: 1
        $x_1_4 = {2f 53 79 73 74 65 6d ?? 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Redosdru_G_2147714344_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Redosdru.G!bit"
        threat_id = "2147714344"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 c6 44 24 ?? 53 c6 44 24 ?? 53 c6 44 24 ?? 53 c6 44 24 ?? 53 c6 44 24 ?? 53 c6 44 24 ?? 56 c6 44 24 ?? 49 c6 44 24 ?? 44}  //weight: 1, accuracy: Low
        $x_1_2 = {44 c6 44 24 ?? 6c c6 44 24 ?? 6c c6 44 24 ?? 46 c6 44 24 ?? 75 c6 44 24 ?? 55 c6 44 24 ?? 70 c6 44 24 ?? 67 c6 44 24 ?? 72 c6 44 24 ?? 61 c6 44 24 ?? 64}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 44 24 08 8d 49 00 8a 08 32 ca 02 ca 88 08 40 83 ee 01 75 f2}  //weight: 1, accuracy: High
        $x_1_4 = {2f c6 44 24 ?? 34 c6 44 24 ?? 2e c6 44 24 ?? 30 c6 44 24 ?? 20 c6 44 24 ?? 28 c6 44 24 ?? 63 c6 44 24 ?? 6f c6 44 24 ?? 6d c6 44 24 ?? 70}  //weight: 1, accuracy: Low
        $x_1_5 = {83 c4 08 3b c3 75 39 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 68 ?? ?? 40 00 68 ?? ?? 40 00 e8 ?? ?? ff ff 83 c4 08 85 c0 74 08 c7 44 24 10 14 00 00 00 8b 4c 24 10 51 ff 15 ?? ?? 40 00 e9 ?? ?? ff ff 68 ?? ?? 40 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Redosdru_H_2147716535_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Redosdru.H!bit"
        threat_id = "2147716535"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 56 c7 45 ?? 53 53 53 53 c7 45 ?? 53 53 56 49 66 c7 45 ?? 44 00}  //weight: 1, accuracy: Low
        $x_2_2 = {8b 45 08 8d 49 00 8a 10 32 d1 02 d1 88 10 40 4e 75 f4}  //weight: 2, accuracy: High
        $x_1_3 = {43 3a 5c 50 c7 45 ?? 72 6f 67 72 c7 45 ?? 61 6d 20 46 c7 45 ?? 69 6c 65 73 c7 45 ?? 5c 41 70 70 66 c7 45 ?? 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {44 6c 6c 46 c7 45 ?? 75 55 70 67 c7 45 ?? 72 61 64 72 66 c7 45 ?? 73 00}  //weight: 1, accuracy: Low
        $x_1_5 = {44 6c 6c 46 c7 45 ?? 75 55 70 67 c7 45 ?? 72 61 64 72 66 c7 45 ?? 73 31 c6 45 ?? 00}  //weight: 1, accuracy: Low
        $x_1_6 = {50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 56 8d 4d ?? 6a 00 c7 45 ?? 57 69 6e 53 c7 45 ?? 74 61 30 5c c7 45 ?? 44 65 66 61 c7 45 ?? 75 6c 74 00}  //weight: 1, accuracy: Low
        $x_1_7 = "\\ServerDat\\Release\\ServerDat.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Redosdru_I_2147717911_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Redosdru.I!bit"
        threat_id = "2147717911"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 08 32 ca 02 ca 88 08 40 4e 75}  //weight: 1, accuracy: High
        $x_1_2 = {44 c6 44 24 ?? 6c c6 44 24 ?? 6c c6 44 24 ?? 46 c6 44 24 ?? 75 c6 44 24 ?? 55 c6 44 24 ?? 70 c6 44 24 ?? 67 c6 44 24 ?? 72 c6 44 24 ?? 61 c6 44 24 ?? 64 c6 44 24 ?? 72 c6 44 24 ?? 73}  //weight: 1, accuracy: Low
        $x_1_3 = {40 00 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4}  //weight: 1, accuracy: Low
        $x_1_4 = {53 c6 44 24 ?? 53 c6 44 24 ?? 53 c6 44 24 ?? 53 c6 44 24 ?? 53 c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Redosdru_J_2147718753_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Redosdru.J!bit"
        threat_id = "2147718753"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 41 00 70 00 70 00 50 00 61 00 74 00 63 00 68 00 [0-16] 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 14 39 80 c2 ?? 80 f2 ?? 88 14 39 41 3b c8 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 45 f1 6f c6 45 f2 74 c6 45 f3 68 c6 45 f4 65 c6 45 f5 72 c6 45 f6 35 c6 45 f7 39 c6 45 f8 39}  //weight: 1, accuracy: High
        $x_1_4 = {79 08 4b 81 cb ?? ?? ?? ?? 43 8a 14 0b 30 10 8b 45 fc 40 3b 45 0c 89 45 fc 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Redosdru_K_2147718951_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Redosdru.K!bit"
        threat_id = "2147718951"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b f8 83 ff ff 0f 84 ?? ?? 00 00 8d 55 ?? 52 c6 45 ?? 53 c6 45 ?? 53 c6 45 ?? 53 c6 45 ?? 53 c6 45 ?? 53 c6 45 ?? 53 c6 45 ?? 00 c6 45 ?? 56 c6 45 ?? 49 c6 45 ?? 44 c6 45 ?? 3a c6 45 ?? 32 c6 45 ?? 30 c6 45 ?? 31}  //weight: 2, accuracy: Low
        $x_2_2 = {85 f6 74 74 8d 4d ?? 51 c6 45 ?? 43 c6 45 ?? 61 c6 45 ?? 6f c6 45 ?? 33 c6 45 ?? 36 c6 45 ?? 30 [0-32] c6 45 ?? 44 c6 45 ?? 6c c6 45 ?? 6c c6 45 ?? 46 c6 45 ?? 75 c6 45 ?? 55 c6 45 ?? 70 c6 45 ?? 67 c6 45 ?? 72 c6 45 ?? 61 c6 45 ?? 64 c6 45 ?? 72 c6 45 ?? 73 c6 45 ?? 00}  //weight: 2, accuracy: Low
        $x_1_3 = {8a 47 01 c1 e6 06 3c 3d 8b de 75 65 8b 44 24 10 83 c0 01 83 f8 03 89 44 24 10 7d 0b 8b d3 c1 fa 10 88 55 00 83 c5 01 83 f8 02 7d 0b 8b cb c1 f9 08 88 4d 00 83 c5 01}  //weight: 1, accuracy: High
        $x_1_4 = "C:\\Program Files\\AppPatch\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Redosdru_L_2147719931_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Redosdru.L!bit"
        threat_id = "2147719931"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 11 04 ?? 34 ?? 88 04 11 83 c1 01 3b ce 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {4b c6 44 24 ?? 6f c6 44 24 ?? 74 c6 44 24 ?? 68 c6 44 24 ?? 65 c6 44 24 ?? 72 c6 44 24 ?? 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Redosdru_M_2147720064_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Redosdru.M!bit"
        threat_id = "2147720064"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 0f b6 14 03 30 14 2f 47 3b 7c 24 1c 72 a7}  //weight: 2, accuracy: High
        $x_1_2 = {51 c6 44 24 ?? 4b c6 44 24 ?? 6f c6 44 24 ?? 74 c6 44 24 ?? 68 c6 44 24 ?? 65 c6 44 24 ?? 72}  //weight: 1, accuracy: Low
        $x_1_3 = {56 c6 44 24 ?? 43 c6 44 24 ?? 61 c6 44 24 ?? 6f c6 44 24 ?? 33 c6 44 24 ?? 36 c6 44 24 ?? 30}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 04 68 00 30 00 00 8b f8 57 53 ff 15 ?? ?? ?? 00 53 8b e8 8d 44 24 ?? 50 57 55 56 ff 15 ?? ?? ?? 00 56 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Redosdru_N_2147721407_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Redosdru.N!bit"
        threat_id = "2147721407"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 ec 80 04 11 ?? 8b 55 ec 80 34 11 ?? 41 3b c8 7c ed}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 44 24 27 2f c6 44 24 28 34 c6 44 24 29 2e c6 44 24 2a 30}  //weight: 1, accuracy: High
        $x_1_3 = {c6 44 24 0c 4b c6 44 24 0d 6f c6 44 24 0e 74 c6 44 24 0f 68 c6 44 24 10 65}  //weight: 1, accuracy: High
        $x_1_4 = {4b c6 44 24 ?? 6f c6 44 24 ?? 74 c6 44 24 ?? 68 c6 44 24 ?? 65 c6 44 24 ?? 72 c6 44 24 ?? 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Redosdru_O_2147722489_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Redosdru.O!bit"
        threat_id = "2147722489"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 0c 03 55 f0 8b 45 08 03 45 f8 8a 0a 32 08 8b 55 0c 03 55 f0 88 0a}  //weight: 1, accuracy: High
        $x_1_2 = {fe ff ff 4b c6 85 ?? fe ff ff 6f c6 85 ?? fe ff ff 74 c6 85 ?? fe ff ff 68 c6 85 ?? fe ff ff 65 c6 85 ?? fe ff ff 72 c6 85 ?? fe ff ff 35 c6 85 ?? fe ff ff 39 c6 85 ?? fe ff ff 39 c6 85 ?? fe ff ff 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 d2 66 8b 11 81 fa 4d 5a 00 00 74 07 33 c0 e9 bc 01 00 00 8b 45 ?? 8b 4d ?? 03 48 3c 89 4d ?? 8b 55 ?? 81 3a 50 45 00 00 74 07 33 c0}  //weight: 1, accuracy: Low
        $x_1_4 = "DllFuUpgradrs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Redosdru_Q_2147724779_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Redosdru.Q!bit"
        threat_id = "2147724779"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c1 33 d2 f7 b4 24 ?? ?? ?? 00 8b bc 24 ?? ?? ?? 00 33 c0 88 0c 31 41 8a 04 3a 8b ?? ?? ?? 89 07 83 c7 04 81 f9 00 01 00 00 89 ?? ?? ?? 7c d0}  //weight: 2, accuracy: Low
        $x_2_2 = {88 04 2e 8a 0c 37 81 e2 ff 00 00 00 03 ca 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 8b 44 24 18 8a 0c 31 8a 14 03 32 d1 88 14 03 8b 44 24 1c 43 3b d8 0f 82 74 ff ff ff}  //weight: 2, accuracy: High
        $x_1_3 = {50 51 c6 44 ?? ?? 4d c6 44 ?? ?? 6f c6 44 ?? ?? 74 c6 44 ?? ?? 68 c6 44 ?? ?? 65 c6 44 ?? ?? 72 c6 44 ?? ?? 33 c6 44 ?? ?? 36 c6 44 ?? ?? 30 c6 44 ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 04 68 00 30 00 00 56 6a 00 ff d7 8d 54 ?? ?? 6a 00 8b f8 52 56 57 55 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_5 = {50 c6 44 24 ?? 44 c6 44 24 ?? 6c c6 44 24 ?? 6c c6 44 24 ?? 46 c6 44 24 ?? 75 c6 44 24 ?? 55 c6 44 24 ?? 70 c6 44 24 ?? 67 c6 44 24 ?? 72 c6 44 24 ?? 61 c6 44 24 ?? 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Redosdru_R_2147725086_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Redosdru.R!bit"
        threat_id = "2147725086"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 8a 14 01 80 c2 ?? 88 14 01 8b 45 fc 8a 14 01 80 f2 ?? 88 14 01 41 3b ce 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 14 01 8b da 81 e3 ff 00 00 00 03 f3 81 e6 ff 00 00 80 79 08 4e 81 ce 00 ff ff ff 46 8a 1c 06 88 54 24 18 88 1c 01 8b 5c 24 18 88 14 06 33 d2 8a 14 01 81 e3 ff 00 00 00 03 d3 81 e2 ff 00 00 80 79 08 4a 81 ca 00 ff ff ff 42 8a 14 02 8a 1c 2f 32 da 8b 54 24 1c 88 1c 2f 47 3b fa 72}  //weight: 1, accuracy: High
        $x_1_3 = {00 4b 6f 74 68 65 72 35 39 39 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 44 6c 6c 46 75 55 70 67 72 61 64 72 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 44 68 6c 4d 65 6d 56 65 72 73 67 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 47 65 74 6f 6e 67 35 33 38 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Redosdru_S_2147725230_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Redosdru.S!bit"
        threat_id = "2147725230"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Kother599" ascii //weight: 1
        $x_1_2 = {8b 4d 08 03 4d ?? 0f b6 11 8b 45 0c 03 45 ?? 0f b6 08 33 ca 8b 55 0c 03 55 ?? 88 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 08 03 55 ?? 8a 45 ?? 88 02 8b 45 ?? 33 d2 f7 75 10 8b 4d 0c 0f b6 14 11 8b 45 ?? 89 94 85}  //weight: 1, accuracy: Low
        $x_1_4 = {eb b0 c6 45 ?? 47 c6 45 ?? 65 c6 45 ?? 74 c6 45 ?? 6f c6 45 ?? 6e c6 45 ?? 67 c6 45 ?? 35 c6 45 ?? 33 c6 45 ?? 38 c6 45 ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Redosdru_Z_2147731964_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Redosdru.Z!bit"
        threat_id = "2147731964"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 44 24 0c 4b c6 44 24 0d 6f c6 44 24 0e 74 c6 44 24 0f 68 c6 44 24 10 65 c6 44 24 11 72 c6 44 24 12 35 c6 44 24 15 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 14 47 c6 44 24 15 65 c6 44 24 16 74 c6 44 24 17 6f c6 44 24 18 6e c6 44 24 19 67 c6 44 24 1a 35 c6 44 24 1b 33 c6 44 24 1c 38}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4c 24 0c 8a 14 08 80 c2 ?? 88 14 08 8b 4c 24 0c 8a 14 08 80 f2 ?? 88 14 08 40 3b c6 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Redosdru_SIB_2147787619_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Redosdru.SIB!MTB"
        threat_id = "2147787619"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 85 c0 7e ?? [0-5] 8b 54 24 ?? 8a 1c 11 80 c3 ?? 88 1c 11 8b 54 24 02 8a 1c 11 80 f3 ?? 88 1c 11 41 3b c8 7c ?? 8b 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 6c 24 18 41 81 e1 ?? ?? ?? ?? 79 ?? 49 81 c9 ?? ?? ?? ?? 41 8a 14 01 8b da 81 e3 ?? ?? ?? ?? 03 f3 81 e6 ?? ?? ?? ?? 79 ?? 4e 81 ce ?? ?? ?? ?? 46 8a 1c 06 88 54 24 18 88 1c 01 8b 5c 24 18 88 14 06 33 d2 8a 14 01 81 e3 ?? ?? ?? ?? 03 d3 81 e2 ?? ?? ?? ?? 79 ?? 4a 81 ca ?? ?? ?? ?? 42 8a 14 02 8a 1c 2f 32 da 8b 54 24 1c 88 1c 2f 47 3b fa 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

