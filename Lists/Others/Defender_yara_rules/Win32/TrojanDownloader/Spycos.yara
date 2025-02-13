rule TrojanDownloader_Win32_Spycos_P_2147630006_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Spycos.P"
        threat_id = "2147630006"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {c1 ed 11 33 dd 03 c3 03 d8 8b e8 c1 e5 09 33 c5 03 d0 03 c2 8b ea c1 ed 03}  //weight: 3, accuracy: High
        $x_3_2 = ":DELBAT" ascii //weight: 3
        $x_1_3 = "M5Se1VSQC7Cl/209GJuMvM6fp" ascii //weight: 1
        $x_1_4 = "4sxXvMSQVOSoW4hwkzdptg" ascii //weight: 1
        $x_1_5 = "gVNhCD3GnrYjnAK3XJSrFA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Spycos_N_2147631441_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Spycos.N"
        threat_id = "2147631441"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_9_1 = {c1 ed 11 33 dd 03 c3 03 d8 8b e8 c1 e5 09 33 c5 03 d0 03 c2 8b ea c1 ed 03}  //weight: 9, accuracy: High
        $x_9_2 = {68 00 00 0a 00 6a 00 6a 00 68 ?? 00 00 00 6a ?? 6a 00 6a 00 ?? 6a 00 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 68 ?? ?? ?? ?? (6a 64|68 ??) 00 00 6a 00 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? eb 0c}  //weight: 9, accuracy: Low
        $x_3_3 = ":DELBAT" ascii //weight: 3
        $x_1_4 = "M5Se1VSQC7Cl/209GJuMvM6fp" ascii //weight: 1
        $x_1_5 = "4sxXvMSQVOSoW4hwkzdptg" ascii //weight: 1
        $x_1_6 = "gVNhCD3GnrYjnAK3XJSrFA" ascii //weight: 1
        $x_1_7 = "HAQv4SZRjJuRUSx7s2L74A==" ascii //weight: 1
        $x_1_8 = "PFoBL+sPmO66jMbUJUKxvrDWd/3skzZUwcque3LBOO0tWkaqvYjxHxsSW0DTB5hWfFyKPok5/lxtrVI2sSU0wEJmxyO9QxjNrcLyiYkiDbU=" ascii //weight: 1
        $x_1_9 = "xzb+sNo3RiuAbbVLnOznP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_9_*) and 1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_9_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Spycos_O_2147641519_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Spycos.O"
        threat_id = "2147641519"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 6b 20 64 6f 77 6c 6f 61 64 65 64 20 63 6f 6e 66 69 67 20 00}  //weight: 2, accuracy: High
        $x_2_2 = {64 6f 77 6c 6f 61 64 20 63 6f 6e 66 69 67 20 69 73 20 66 61 69 6c 20 00}  //weight: 2, accuracy: High
        $x_2_3 = {6f 6b 20 64 6f 77 6c 6f 61 64 65 64 20 64 6c 6c 20 00}  //weight: 2, accuracy: High
        $x_1_4 = "gVNhCD3GnrYjnAK3XJSrFA" ascii //weight: 1
        $x_1_5 = "M5Se1VSQC7Cl/209GJuMvM6fp" ascii //weight: 1
        $x_1_6 = {49 4e 4f 56 41 4e 44 4f 4f 4f 4f 2e 2e 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Spycos_E_2147644603_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Spycos.E"
        threat_id = "2147644603"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 6e 73 74 61 6c 65 72 7a 65 63 70 6c 2e 63 70 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {65 6d 33 63 79 34 4c 6d 53 6f 50 52 44 50 76 56 34 74 54 51 74 41 3d 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {51 33 62 74 61 50 43 6c 64 49 62 77 2b 62 6f 63 7a 37 36 43 77 4a 64 65 36 70 78 62 5a 52 41 61 63 53 77 65 74 2b 59 70 7a 35 38 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {4c 59 61 79 67 71 63 37 66 6b 66 78 70 42 68 34 5a 37 77 77 6a 77 3d 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 00}  //weight: 1, accuracy: High
        $x_1_6 = {49 4e 4f 56 41 4e 44 4f 4f 4f 4f 2e 2e 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Spycos_I_2147647896_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Spycos.I"
        threat_id = "2147647896"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 6d 65 6e 73 61 67 65 6d 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {41 56 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 3a 20 4e 4f 52 54 45 00}  //weight: 1, accuracy: High
        $x_1_3 = {50 6c 75 67 69 6e 20 52 45 44 2e 2e 2e 2e 2e 2e 3a 20 (53|41 56 47 49 4e)}  //weight: 1, accuracy: Low
        $x_1_4 = {52 45 45 4e 56 49 4f 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = "ZALSc7aJVnSXnH0XNr/vwQ==" ascii //weight: 1
        $x_1_6 = "Aa2eBspfYBgsu9UtnF5nWg==" ascii //weight: 1
        $x_1_7 = "t/Kblhy52U6fAC7GlDjS7e9dwRjfYAXY/ECeQWnZHuQ=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Spycos_H_2147648894_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Spycos.H"
        threat_id = "2147648894"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {35 ae ca 7b c3 ff 25 ?? ?? ?? ?? 8b c0 53 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75}  //weight: 2, accuracy: Low
        $x_1_2 = "inovandoooo..." ascii //weight: 1
        $x_1_3 = {74 69 70 6f 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {50 6c 75 67 69 6e 20 52 45 44 2e 2e 2e 2e 2e 2e 3a 20 (53|41 56 47 49 4e)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Spycos_D_2147653024_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Spycos.D"
        threat_id = "2147653024"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 3d 16 04 74 20 8d 95 ?? fe ff ff b8 ?? ?? ?? ?? e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 40 0d 03 00 5a e8 ?? ?? ff ff 84 c0 0f 84}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 53 8d 55 e8 b9 10 00 00 00 8b 45 fc e8 ?? ?? ?? ff 33 c0 5a 59 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Spycos_A_2147655313_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Spycos.A"
        threat_id = "2147655313"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "5451505A165B5952" ascii //weight: 1
        $x_1_2 = "54555050165E5752" ascii //weight: 1
        $x_1_3 = "5F52525C1855575E" ascii //weight: 1
        $x_1_4 = "7D66657C187679157C7E77717770756A17" ascii //weight: 1
        $x_1_5 = "7D62657618737715717A7B707570766117" ascii //weight: 1
        $x_1_6 = "7665677A16787719717A7571757C796718" ascii //weight: 1
        $x_1_7 = "7D5A565154527A6074" ascii //weight: 1
        $x_1_8 = "7D5E565B5457746079" ascii //weight: 1
        $x_1_9 = "50444349021D17" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Spycos_B_2147655775_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Spycos.B"
        threat_id = "2147655775"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 55 f8 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f8 e8 ?? ?? ?? ?? 50 68 01 00 00 80 e8}  //weight: 5, accuracy: Low
        $x_5_2 = {8d 55 ec b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ec e8 ?? ?? ?? ?? 50 68 01 00 00 80 e8}  //weight: 5, accuracy: Low
        $x_5_3 = {66 3d 16 04 74 20 8d 95 24 fe ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 85 24 fe ff ff e8}  //weight: 5, accuracy: Low
        $x_5_4 = {66 3d 16 04 74 1a 8d 55 ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 00 e8}  //weight: 5, accuracy: Low
        $x_5_5 = {b9 40 0d 03 00 5a e8 ?? ?? ff ff 84 c0 0f 84 ?? ?? 00 00 [0-32] 33 c9 b2 01}  //weight: 5, accuracy: Low
        $x_1_6 = {8b 55 ac 8b c3 8b 08 ff 51 74 6a 00 8d 55 9c a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 9c 8d 55 a0}  //weight: 1, accuracy: Low
        $x_1_7 = {74 e8 8d 45 f4 50 8b 85 9c fc ff ff 50 16 00 68 e8 03 00 00 8b 85 9c fc ff ff 50 e8 ?? ?? ?? ?? 3d 02 01 00 00}  //weight: 1, accuracy: Low
        $x_1_8 = {22 20 2d 75 00 00 00 00 0e 00 3d 3d 00 00 00 00 ff ff ff ff 04 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Spycos_G_2147655907_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Spycos.G"
        threat_id = "2147655907"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 20 2d 75 1c 00 0d 00 00 00 72 65 67 73 76 72 33 32 20 2f 73 20 22 00 00 00 ff ff ff ff 04 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {22 20 2d 75 00 00 00 00 ff ff ff ff 06 00 00 00 41 43 20 52 45 47 00 0e 00 3d 3d 00 00 00 00 ff ff ff ff 04 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Spycos_J_2147656010_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Spycos.J"
        threat_id = "2147656010"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 45 e0 8b 45 e8 33 45 e0 89 45 e4 8d 45 d4 8b 55 e4 e8 ?? ?? ?? ?? 8b 55 d4 8b 45 ec e8}  //weight: 3, accuracy: Low
        $x_2_2 = {66 3d 16 04 74 20 8d 95 ?? fe ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 85 ?? fe ff ff}  //weight: 2, accuracy: Low
        $x_2_3 = {83 f8 06 7f 21 0f 84 d0 00 00 00 48 74 3b 48 74 55 48 0f 84 93 00 00 00 83 e8 02 0f 84 aa 00 00 00 e9 e3 00 00 00}  //weight: 2, accuracy: High
        $x_1_4 = {2e 63 70 6c 0d 0a 45 72 61 73 65 20 22 43 3a 5c}  //weight: 1, accuracy: High
        $x_1_5 = {69 6e 73 74 61 6c 65 72 2e 63 70 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {63 70 6c 4d 69 6e 69 2e 63 70 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Spycos_R_2147663539_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Spycos.R"
        threat_id = "2147663539"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {bb 01 00 00 00 e9 a3 00 00 00 8b 45 f8 0f b6 44 38 ff 89 45 e8 47 8b 75 f8 85 f6 74 05 83 ee 04 8b 36 3b f7 7d 05 bf 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 45 e8 33 45 e0 89 45 e4 8d 45 cc}  //weight: 10, accuracy: Low
        $x_5_2 = {22 20 2d 75 00 30 00 34 ?? 00 00 ff ff ff ff 18 00}  //weight: 5, accuracy: Low
        $x_1_3 = {43 6f 6e 74 72 6f 6c 50 61 6e 65 6c 43 70 6c 2e 63 70 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {70 64 6c 6c 69 6e 73 74 61 6c 65 72 2e 64 6c 6c 00 69 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = "UPD 10 DISCARDABLE \"htmlgrd.exe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

