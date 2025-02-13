rule TrojanDownloader_Win32_Dofoil_A_160314_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.A"
        threat_id = "160314"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 8d 85 06 05 00 00 50 ff 95 d6 04 00 00 09 c0 74 24 89 c3 8d b5 ee 04 00 00 e8 ?? ?? 00 00 8d 9d 4e 05 00 00 8d 85 81 05 00 00 89 85 9e 05 00 00 e8 08 00 00 00 6a 00 ff 95 e6 04 00 00 8d bd a2 05 00 00 8d b5 1c 05 00 00 e8 ?? ?? 00 00 01 cf 4f 89 de e8 ?? ?? 00 00 8d 85 12 05 00 00 6a 00 6a 00 6a 00 6a 00 50 ff 95 ee 04 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_D_160826_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.D"
        threat_id = "160826"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f2 bc 67 53 6f 75 e4 8b 5f 08 8d b5 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d bd ?? ?? ?? ?? 8d b5 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 ff 95 ?? ?? ?? ?? 89 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {46 32 06 aa e0 fa f7 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_G_163750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.G"
        threat_id = "163750"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4f 75 72 5f 41 67 65 6e 74 00 5c 64 78 64 69 61 67 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 00 53 74 61 72 74 75 70}  //weight: 1, accuracy: High
        $x_1_3 = {3f 62 69 64 3d 25 30 38 78 25 30 38 78 00 26 6f 73 3d 25 64 2d 25 64 2d 25 64 00 26 75 70 74 69 6d 65 3d 25 64 26 72 6e 64 3d 25 64 00 25 78 25 78 25 73}  //weight: 1, accuracy: High
        $x_1_4 = "download1" ascii //weight: 1
        $x_1_5 = {75 70 64 61 74 65 63 09 20}  //weight: 1, accuracy: High
        $x_1_6 = "\\Startup\\dxdiag.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_A_164230_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.gen!A"
        threat_id = "164230"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 c9 74 16 49 74 13 ba ?? ?? ?? ?? 8b 75 08 4a ac 32 07 aa}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4e 50 c1 e9 02 31 c0 f3 ab 0f b7 5e 06 b8 28 00 00 00 f7 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_L_166033_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.L"
        threat_id = "166033"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 03 50 e8 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 68}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 0c 50 a1 ?? ?? ?? ?? 8b 00 ff d0 3d 03 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_L_166033_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.L"
        threat_id = "166033"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?cmd=getload&" ascii //weight: 1
        $x_1_2 = {eb 08 e8 09 00 00 00 89 46 fc ad 85 c0 75 f3 c3 56 89 c2 8b 45 3c 8b 7c 28 78 01 ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_L_166033_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.L"
        threat_id = "166033"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 03 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {89 83 b0 00 00 00}  //weight: 1, accuracy: High
        $x_2_3 = {8a 06 32 c2 88 07 46 47 49 83 f9 00 75 f2}  //weight: 2, accuracy: High
        $x_1_4 = {68 56 71 64 4f 8b 03 50 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Dofoil_M_166524_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.M"
        threat_id = "166524"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {58 87 04 24 8b 04 03 0f c8 ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {83 c6 02 0f b7 16 31 d0 66 ab 49 75 f3}  //weight: 1, accuracy: High
        $x_1_3 = {ff e0 03 76 3c 8d 7e 78 8d 55}  //weight: 1, accuracy: High
        $x_1_4 = {29 c2 89 d0 c1 c0 08 88 c2 b0 e9 89 06}  //weight: 1, accuracy: High
        $x_1_5 = {56 31 d2 ac 00 c2 c1 c2 11 ac 08 c0 75 f6}  //weight: 1, accuracy: High
        $x_1_6 = {4f 75 72 5f 41 67 65 6e 74 00 5c 63 74 66 6d 6f 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_C_168560_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.gen!C"
        threat_id = "168560"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 72 6b 00 00 68 00 00 57 6f}  //weight: 1, accuracy: High
        $x_1_2 = {b0 68 aa 8b 45 fc ab b0 c3 aa}  //weight: 1, accuracy: High
        $x_1_3 = {e2 ea eb d4 61 89 c5 8d bb ?? ?? ?? ?? 03 80 78 01 00 00 8b 48 14 0b 48 18 74 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_R_174260_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.R"
        threat_id = "174260"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c7 04 05 00 00 b8 43 6b 7e 0a ab b8 5a 3f 23 65 ab}  //weight: 1, accuracy: High
        $x_1_2 = {b0 68 aa 8b 45 ?? ab b0 c3 aa}  //weight: 1, accuracy: Low
        $x_1_3 = {81 c7 00 12 00 00 66 c7 07 57 6f 66 c7 47 02 72 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_D_180729_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.gen!D"
        threat_id = "180729"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 28 c1 c1 08 32 cd 40 80 38 00 75 f3 31 d1 75}  //weight: 1, accuracy: High
        $x_1_2 = {6a 40 68 00 30 00 00 8b 46 50 50 6a 00 ff 93}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_T_195234_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.T"
        threat_id = "195234"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 51 8b 34 8a 01 de 89 f0 31 c9 32 28 c1 c1 08 32 cd 40 80 38 00 75 f3}  //weight: 1, accuracy: High
        $x_1_2 = {8a 1b 32 1e 88 5c 24 04 2a 4c 24 04 33 db 8a d8 03 1c 24 4b 88 0b 47 40 fe ca 75 d3}  //weight: 1, accuracy: High
        $x_1_3 = {25 00 73 00 5c 00 25 00 73 00 00 00 25 00 73 00 25 00 73 00 00 00 00 00 72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 20 00 2f 00 73 00 20 00 25 00 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {63 6d 64 3d 67 65 74 6c 6f 61 64 26 6c 6f 67 69 6e 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {26 70 65 72 73 6f 6e 61 6c 3d 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_6 = {26 72 75 6e 3d 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_U_195330_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.U"
        threat_id = "195330"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 28 c1 c1 08 32 cd 40 80 38 00 75 f3}  //weight: 1, accuracy: High
        $x_1_2 = {66 c7 07 57 6f 66 c7 47 02 72 6b}  //weight: 1, accuracy: High
        $x_1_3 = {ac 32 c2 aa e2 fa}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 fc 43 3a 5c 00 8d 45 fc 8d 4d f8 56 56 56 56 51 68 80 00 00 00 56 50 ff 15}  //weight: 1, accuracy: High
        $x_1_5 = {83 c0 04 8b 00 89 45 fc 8b 45 fc 35 de c0 ad de}  //weight: 1, accuracy: High
        $x_1_6 = {8a 1b 32 1e 88 5c 24 04 2a 4c 24 04 33 db 8a d8 03 1c 24 4b 88 0b}  //weight: 1, accuracy: High
        $x_1_7 = {b8 5a 00 00 00 e8 44 ?? ?? ?? ?? 04 20 88 04 37 46 4b 75 ed}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_W_200036_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.W"
        threat_id = "200036"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 6d 6b 00 06 00 c7 87 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {60 89 c5 89 d3 8b 7b 3c 8b 7c 1f 78 01 df}  //weight: 1, accuracy: High
        $x_1_3 = {81 c7 00 12 00 00 66 c7 07 57 6f 66 c7 47 02 72 6b}  //weight: 1, accuracy: High
        $x_1_4 = {81 7d 00 40 1a cd 00 74 09 81 7d 00 46 46 14 70 75 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_T_206968_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.T!!Dofoil.gen!A"
        threat_id = "206968"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "Dofoil: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 51 8b 34 8a 01 de 89 f0 31 c9 32 28 c1 c1 08 32 cd 40 80 38 00 75 f3}  //weight: 1, accuracy: High
        $x_1_2 = {8a 1b 32 1e 88 5c 24 04 2a 4c 24 04 33 db 8a d8 03 1c 24 4b 88 0b 47 40 fe ca 75 d3}  //weight: 1, accuracy: High
        $x_1_3 = "cmd=getload&login=" ascii //weight: 1
        $x_1_4 = {26 70 65 72 73 6f 6e 61 6c 3d 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {26 72 65 6d 6f 76 65 64 3d 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00}  //weight: 1, accuracy: Low
        $x_1_7 = {25 00 73 00 5c 00 25 00 73 00 00 00 25 00 73 00 25 00 73 00 00 00 00 00 72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 20 00 2f 00 73 00 20 00 25 00 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_U_227974_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.U!!Dofoil.gen!A"
        threat_id = "227974"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "Dofoil: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 28 c1 c1 08 32 cd 40 80 38 00 75 f3}  //weight: 1, accuracy: High
        $x_1_2 = {66 c7 07 57 6f 66 c7 47 02 72 6b}  //weight: 1, accuracy: High
        $x_1_3 = {ac 32 c2 aa e2 fa}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 fc 43 3a 5c 00 8d 45 fc 8d 4d f8 56 56 56 56 51 68 80 00 00 00 56 50 ff 15}  //weight: 1, accuracy: High
        $x_1_5 = {83 c0 04 8b 00 89 45 fc 8b 45 fc 35 de c0 ad de}  //weight: 1, accuracy: High
        $x_1_6 = {8a 1b 32 1e 88 5c 24 04 2a 4c 24 04 33 db 8a d8 03 1c 24 4b 88 0b}  //weight: 1, accuracy: High
        $x_1_7 = {b8 5a 00 00 00 e8 44 ?? ?? ?? ?? 04 20 88 04 37 46 4b 75 ed}  //weight: 1, accuracy: Low
        $x_1_8 = {68 72 6b 00 00 68 00 00 57 6f 89 e6}  //weight: 1, accuracy: High
        $x_1_9 = {81 3c 24 40 1a cd 00 74 09 81 3c 24 46 46 14 70 75 05}  //weight: 1, accuracy: High
        $x_1_10 = "%d#%s#%s#%d.%d#%d#%d#%d#%d#%" ascii //weight: 1
        $x_1_11 = {00 73 76 63 56 65 72 73 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 70 6c 75 67 69 6e 5f 73 69 7a 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_U_238226_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.U!bit"
        threat_id = "238226"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 07 88 10 8b 55 fc 41 40 3b ca 72 f2 68 ?? ?? ?? ?? 6a 40 52 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {30 14 30 40 3b 45 fc 7c e6 89 0d ?? ?? ?? ?? ff 55 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_V_238799_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.V!bit"
        threat_id = "238799"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 ca 8a 0c 01 8b 35 ?? ?? ?? 00 83 c6 03 0f af 75 ?? 03 75 ?? 88 0c 02 83 c0 01 3b 45 ?? 89 75 ?? 7c ce}  //weight: 2, accuracy: Low
        $x_2_2 = {8b c6 2b c1 83 e8 04 0f af c7 8b 5d ?? 8b 7d ?? 83 c2 01 8d 48 03 0f af ca 8b 55 ?? 0f af ce 2b d9 8a 0c 17 32 cb 85 f6 74 05 88 0c 17 eb 03 88 14 17}  //weight: 2, accuracy: Low
        $x_1_3 = {5f 5e 5b 8b e5 5d c2 10 00 05 00 8b 6d ?? ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Dofoil_AA_240168_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.AA"
        threat_id = "240168"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 45 fc 10 00 00 00 ff 15 ?? ?? ?? ?? c7 45 ?? 25 30 32 58}  //weight: 2, accuracy: Low
        $x_2_2 = {25 73 5c 25 66 89 45 ?? c7 45 ?? 68 74 74 70}  //weight: 2, accuracy: Low
        $x_1_3 = {50 57 c7 44 24 1c 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = {74 0a 83 c1 04 83 f9 30 72 f0 eb 09}  //weight: 1, accuracy: High
        $x_1_5 = {6a 08 59 0f be 10 8a 54 15 ?? 88 10 40 49 75 f3}  //weight: 1, accuracy: Low
        $x_2_6 = {6a 07 66 89 45 ?? 8b 45 ?? 2b df 8d 4d ?? 51 03 f8 2b d8 57 ff 75 08 83 eb 07 c6 45 ?? e9}  //weight: 2, accuracy: Low
        $x_2_7 = {8d 5d f8 c7 45 f8 2e 62 69 74 c6 45 fc 00 e8 ?? ?? ?? ?? 5b 83 f8 ff 74 0f 8a 44 30 03 3c 3a 74 04 3c 2f 75 03}  //weight: 2, accuracy: Low
        $x_1_8 = {8b 47 04 35 e7 e0 c0 9f 0f 85}  //weight: 1, accuracy: High
        $x_1_9 = {81 7d fc 40 1a cd 00 74 d9 81 7d fc 46 46 14 70 74 d0}  //weight: 1, accuracy: High
        $x_1_10 = {3d 40 44 1e 42 74 11 3d 44 47 19 44 75 12}  //weight: 1, accuracy: High
        $x_1_11 = {25 73 25 73 88 5d f4 c7 45 f8 46 46 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Dofoil_AB_242569_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.AB"
        threat_id = "242569"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lsmrcaeA" ascii //weight: 1
        $x_1_2 = "mnH122" ascii //weight: 1
        $x_1_3 = "TknjQt34-fse+dgf.111h12" ascii //weight: 1
        $x_1_4 = "gipOoZaUyi" ascii //weight: 1
        $x_1_5 = "VQSolLUbiJ" ascii //weight: 1
        $x_1_6 = "9Eetmcmpi_thx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_AB_242569_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.AB"
        threat_id = "242569"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 1a cd 00 0f 84 ?? ?? 00 00 81 7d ?? 46 46 14 70}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 40 44 1e 42 74 ?? 3d 44 47 19 44}  //weight: 1, accuracy: Low
        $x_1_3 = {3c 69 0f 84 ?? ?? 00 00 3c 72 0f 84 ?? ?? 00 00 3c 75 74}  //weight: 1, accuracy: Low
        $x_2_4 = {c6 44 24 32 e9 51 b8 90 90 00 00 8d 4c 24 34 66 89 44 24 34}  //weight: 2, accuracy: High
        $x_2_5 = {c6 04 48 2f b9 00 01 80 00 83 7c 24 ?? 02 b8 00 01 00 00 0f 44 c1 50 6a 00 6a 00 6a 00 ff 74 24 ?? 56 53 ff 15 ?? ?? ?? ?? 8b f0 85 f6 0f 84 ?? ?? 00 00 83 7c 24 ?? 02 75 ?? 6a 04 8d 44 24 ?? c7 44 24 ?? 00 33 00 00}  //weight: 2, accuracy: Low
        $x_1_6 = {44 3a 50 00 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_7 = {25 73 5c 25 04 00 c7 44 24}  //weight: 1, accuracy: Low
        $x_1_8 = {68 74 74 70 04 00 c7 44 24}  //weight: 1, accuracy: Low
        $x_1_9 = {25 30 32 58 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_10 = {2e 62 69 74 03 00 c7 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Dofoil_AD_242629_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.AD"
        threat_id = "242629"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 1c 25 73 25 73}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 20 46 46 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 44 24 10 2e 65 78 65}  //weight: 1, accuracy: High
        $x_2_4 = {25 30 38 58 88 ?? ec 89 ?? e4 89 ?? e8 8b 45 fc 35}  //weight: 2, accuracy: Low
        $x_2_5 = {8b 0f 8d 77 04 89 4c 24 ?? 80 f9 3c 74 04 3b c8 7c 08 3b c8 0f 8d ?? ?? 00 00 6a 04 51 8d 54 24 ?? c7 44 24}  //weight: 2, accuracy: Low
        $x_1_6 = {c7 44 24 10 7c 3a 7c 00}  //weight: 1, accuracy: High
        $x_1_7 = {c7 44 24 18 25 73 00 00}  //weight: 1, accuracy: High
        $x_2_8 = {b8 4d 5a 00 00 66 39 03 0f 85 ?? ?? 00 00 81 fd 00 02 00 00 0f 8e ?? ?? 00 00 b9 08 02 00 00 e8 ?? ?? 00 00 83 3d ?? ?? ?? ?? 04 8b e8 75}  //weight: 2, accuracy: Low
        $x_1_9 = {25 73 25 73 07 00 c7 84 24}  //weight: 1, accuracy: Low
        $x_1_10 = {c7 46 01 3a 64 07 b2}  //weight: 1, accuracy: High
        $x_1_11 = {25 30 32 78 04 00 c7 44 24}  //weight: 1, accuracy: Low
        $x_1_12 = {3a 64 07 b2 07 00 c7 84 24}  //weight: 1, accuracy: Low
        $x_1_13 = {2e 62 69 74 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_2_14 = {25 73 25 30 68 ?? ?? ?? ?? 8d 45 ?? c7 45 f0 38 58 25 30 50 8d 45 ?? c7 45 ?? 38 58 00 00}  //weight: 2, accuracy: Low
        $x_1_15 = {25 30 32 58 03 00 c7 45}  //weight: 1, accuracy: Low
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

rule TrojanDownloader_Win32_Dofoil_AA_243231_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.AA!!Dofoil.gen!B"
        threat_id = "243231"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "Dofoil: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 45 fc 10 00 00 00 ff 15 ?? ?? ?? ?? c7 45 ?? 25 30 32 58}  //weight: 2, accuracy: Low
        $x_2_2 = {25 73 5c 25 66 89 45 ?? c7 45 ?? 68 74 74 70}  //weight: 2, accuracy: Low
        $x_1_3 = {50 57 c7 44 24 1c 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = {74 0a 83 c1 04 83 f9 30 72 f0 eb 09}  //weight: 1, accuracy: High
        $x_1_5 = {6a 08 59 0f be 10 8a 54 15 ?? 88 10 40 49 75 f3}  //weight: 1, accuracy: Low
        $x_2_6 = {6a 07 66 89 45 ?? 8b 45 ?? 2b df 8d 4d ?? 51 03 f8 2b d8 57 ff 75 08 83 eb 07 c6 45 ?? e9}  //weight: 2, accuracy: Low
        $x_2_7 = {8d 5d f8 c7 45 f8 2e 62 69 74 c6 45 fc 00 e8 ?? ?? ?? ?? 5b 83 f8 ff 74 0f 8a 44 30 03 3c 3a 74 04 3c 2f 75 03}  //weight: 2, accuracy: Low
        $x_1_8 = {8b 47 04 35 e7 e0 c0 9f 0f 85}  //weight: 1, accuracy: High
        $x_1_9 = {81 7d fc 40 1a cd 00 74 d9 81 7d fc 46 46 14 70 74 d0}  //weight: 1, accuracy: High
        $x_1_10 = {3d 40 44 1e 42 74 11 3d 44 47 19 44 75 12}  //weight: 1, accuracy: High
        $x_1_11 = {25 73 25 73 88 5d f4 c7 45 f8 46 46 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Dofoil_AB_243232_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.AB!!Dofoil.gen!B"
        threat_id = "243232"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "Dofoil: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 1a cd 00 0f 84 ?? ?? 00 00 81 7d ?? 46 46 14 70}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 40 44 1e 42 74 ?? 3d 44 47 19 44}  //weight: 1, accuracy: Low
        $x_1_3 = {3c 69 0f 84 ?? ?? 00 00 3c 72 0f 84 ?? ?? 00 00 3c 75 74}  //weight: 1, accuracy: Low
        $x_2_4 = {c6 44 24 32 e9 51 b8 90 90 00 00 8d 4c 24 34 66 89 44 24 34}  //weight: 2, accuracy: High
        $x_2_5 = {c6 04 48 2f b9 00 01 80 00 83 7c 24 ?? 02 b8 00 01 00 00 0f 44 c1 50 6a 00 6a 00 6a 00 ff 74 24 ?? 56 53 ff 15 ?? ?? ?? ?? 8b f0 85 f6 0f 84 ?? ?? 00 00 83 7c 24 ?? 02 75 ?? 6a 04 8d 44 24 ?? c7 44 24 ?? 00 33 00 00}  //weight: 2, accuracy: Low
        $x_1_6 = {44 3a 50 00 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_7 = {25 73 5c 25 04 00 c7 44 24}  //weight: 1, accuracy: Low
        $x_1_8 = {68 74 74 70 04 00 c7 44 24}  //weight: 1, accuracy: Low
        $x_1_9 = {25 30 32 58 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_10 = {2e 62 69 74 03 00 c7 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Dofoil_AD_243233_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.AD!!Dofoil.gen!B"
        threat_id = "243233"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "Dofoil: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 1c 25 73 25 73}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 20 46 46 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 44 24 10 2e 65 78 65}  //weight: 1, accuracy: High
        $x_2_4 = {25 30 38 58 88 ?? ec 89 ?? e4 89 ?? e8 8b 45 fc 35}  //weight: 2, accuracy: Low
        $x_2_5 = {8b 0f 8d 77 04 89 4c 24 ?? 80 f9 3c 74 04 3b c8 7c 08 3b c8 0f 8d ?? ?? 00 00 6a 04 51 8d 54 24 ?? c7 44 24}  //weight: 2, accuracy: Low
        $x_1_6 = {c7 44 24 10 7c 3a 7c 00}  //weight: 1, accuracy: High
        $x_1_7 = {c7 44 24 18 25 73 00 00}  //weight: 1, accuracy: High
        $x_2_8 = {b8 4d 5a 00 00 66 39 03 0f 85 ?? ?? 00 00 81 fd 00 02 00 00 0f 8e ?? ?? 00 00 b9 08 02 00 00 e8 ?? ?? 00 00 83 3d ?? ?? ?? ?? 04 8b e8 75}  //weight: 2, accuracy: Low
        $x_1_9 = {25 73 25 73 07 00 c7 84 24}  //weight: 1, accuracy: Low
        $x_1_10 = {c7 46 01 3a 64 07 b2}  //weight: 1, accuracy: High
        $x_1_11 = {25 30 32 78 04 00 c7 44 24}  //weight: 1, accuracy: Low
        $x_1_12 = {3a 64 07 b2 07 00 c7 84 24}  //weight: 1, accuracy: Low
        $x_1_13 = {2e 62 69 74 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_2_14 = {25 73 25 30 68 ?? ?? ?? ?? 8d 45 ?? c7 45 f0 38 58 25 30 50 8d 45 ?? c7 45 ?? 38 58 00 00}  //weight: 2, accuracy: Low
        $x_1_15 = {25 30 32 58 03 00 c7 45}  //weight: 1, accuracy: Low
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

rule TrojanDownloader_Win32_Dofoil_AE_244396_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.AE"
        threat_id = "244396"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 75 06 74 04 ?? ?? ?? ?? 5b eb}  //weight: 1, accuracy: Low
        $x_1_2 = {83 b8 a4 00 00 00 06 7c ?? eb}  //weight: 1, accuracy: Low
        $x_2_3 = {0f b6 40 02 eb ?? ?? 40 eb ?? ?? ?? ?? ?? b9 ?? ?? ?? ?? eb ?? ?? ?? ?? ?? eb ?? ?? eb ?? ?? f7 e1 eb ?? ?? ?? ?? ?? ?? 01 d8 74 07 75 05 ?? ?? ?? ?? ?? 50 c3}  //weight: 2, accuracy: Low
        $x_2_4 = {0f b6 46 68 eb ?? ?? 40 74 07 75 05 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 75 04 74 02 ?? ?? 59 eb ?? ?? f7 e1 eb ?? ?? ?? ?? ?? ?? 01 d8 eb ?? ?? ?? ?? ff e0}  //weight: 2, accuracy: Low
        $x_4_5 = {e8 00 00 00 00 75 06 74 04 ?? ?? ?? ?? 5e eb ?? ?? 81 ee ?? ?? ?? ?? eb ?? ?? eb ?? ?? ?? eb ?? ?? ?? ?? ?? ?? 01 c6 eb ?? ?? ?? ?? ?? 89 f7 eb ?? ?? ?? ?? ?? eb ?? ?? ac eb ?? ?? ?? ?? ?? ?? 30 d0 aa e2 ?? 75 06 74 04}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_AF_244907_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.AF!bit"
        threat_id = "244907"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 75 06 74 04 ?? ?? ?? ?? 5b eb}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 40 02 eb ?? ?? 40 eb ?? ?? ?? ?? ?? b9 ?? ?? ?? ?? eb ?? ?? ?? ?? ?? eb ?? ?? eb ?? ?? f7 e1 eb ?? ?? ?? ?? ?? ?? 01 d8 74 07 75 05 ?? ?? ?? ?? ?? 50 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {89 ce 83 e6 03 75 0c 8b 5d 10 66 01 da c1 ca 03 89 55 10 30 10 40 c1 ca 08 e2 e4}  //weight: 1, accuracy: High
        $x_1_4 = {8a 10 80 ca 60 01 d3 d1 e3 03 45 10 8a 08 84 c9 e0 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_AG_247858_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.AG!bit"
        threat_id = "247858"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 ?? 40 89 45 ?? 8b 85 ?? ff ff ff 8b 84 85 ?? ?? ff ff 8b 4d ?? 0f be 04 08 0f b6 4d ?? 33 c1 8b 4d ?? 03 4d ?? 88 01 8b 45 ?? 03 45 ?? 0f be 00 85 c0 75 02 eb 02 eb c6}  //weight: 1, accuracy: Low
        $x_1_2 = "client_id=%.8x&connected=%d&server_port=%d&debug=%d&os=%d.%d.%04d&dgt=%d" ascii //weight: 1
        $x_1_3 = "/single.php?c=%s" ascii //weight: 1
        $x_1_4 = "heyfg645fdhwi" ascii //weight: 1
        $x_1_5 = "\\lock.dat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_AH_250647_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.AH!bit"
        threat_id = "250647"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 b8 a4 00 00 00 06 [0-48] 89 c6}  //weight: 1, accuracy: Low
        $x_1_2 = {30 d0 aa e2 ?? 75}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 46 68 eb [0-32] 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_AI_251748_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.AI!bit"
        threat_id = "251748"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 51 8b 34 8a 01 de 89 f0 31 c9 32 28 c1 c1 08 32 cd 40 80 38 00 75 f3}  //weight: 2, accuracy: High
        $x_2_2 = {8a 1b 32 1e 88 5c 24 04 2a 4c 24 04 33 db 8a d8 03 1c 24 4b 88 0b 47 40 fe ca 75 d3}  //weight: 2, accuracy: High
        $x_2_3 = {8a d1 0f b6 94 15 ?? ?? ?? ?? 8b f3 81 e6 ff 00 00 00 0f b6 b4 35 ?? ?? ?? ?? 03 d6 81 e2 ff 00 00 00 32 84 15 ?? ?? ?? ?? 8b 55 ?? 8b 75 ?? 88 04 32}  //weight: 2, accuracy: Low
        $x_1_4 = {25 00 73 00 5c 00 25 00 73 00 00 00 25 00 73 00 25 00 73 00 00 00 00 00 72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 20 00 2f 00 73 00 20 00 25 00 73 00}  //weight: 1, accuracy: High
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Dofoil_BM_258052_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.BM!MTB"
        threat_id = "258052"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e6 ff 00 00 00 33 ff 89 35 ?? ?? ?? ?? 81 fa 56 0e 00 00 8a 9e ?? ?? ?? ?? 0f 44 c7 a3 ?? ?? ?? ?? 8a 81 ?? ?? ?? ?? 88 86 ?? ?? ?? ?? 88 5c 24 0f 88 99 ?? ?? ?? ?? 81 fa ab 0c 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 3e 4e 79 f5 8b 8c 24 30 08 00 00 5f 5e 5d 5b 33 cc e8 ?? ?? ?? ?? 81 c4 24 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_B_279114_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.B!MTB"
        threat_id = "279114"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 40 02 eb ?? ?? 40 eb ?? ?? ?? ?? ?? b9 ?? ?? ?? ?? eb ?? ?? ?? ?? ?? eb ?? ?? eb ?? ?? f7 e1 eb ?? ?? ?? ?? ?? ?? 01 d8 74 07 75 05 ?? ?? ?? ?? ?? 50 c3}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 4c 24 04 57 f7 c1 03 00 00 00 74 ?? 8a 01 41 84 c0 74 ?? f7 c1 03 00 00 00 75 ?? 8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04 a9 00 01 01 81}  //weight: 2, accuracy: Low
        $x_1_3 = "\\drivers\\tcpip.sys" ascii //weight: 1
        $x_1_4 = "drivers\\beep.sys" ascii //weight: 1
        $x_1_5 = "dump_dumpfve.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_AS_328526_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.AS"
        threat_id = "328526"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a1 08 cf 45 00 89 45 f8 81 45 f8 43 0d 00 00 8b 45 f8 a3 08 cf 45 00 ff 15 08 cf 45 00}  //weight: 1, accuracy: High
        $x_1_2 = {a1 0c cf 45 00 8a 8c 10 76 f1 08 00 a1 08 cf 45 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_AT_329332_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.AT"
        threat_id = "329332"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fa f7 13 00 00 75 ?? 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {b1 6d b0 6c 68 68 91 47 00 88 [0-5] c6 ?? ?? ?? ?? ?? 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_AU_329333_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.AU"
        threat_id = "329333"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 e7 df 00 00 83 c4 04 68 1a 04 00 00 ff d7 6a 00 e8 e9 dc 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 68 df e2 f0 01 e8 4e fb ff ff}  //weight: 1, accuracy: High
        $x_1_3 = "HellStar.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_AU_329333_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.AU"
        threat_id = "329333"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://zzzip.tiny.us/max02154a" wide //weight: 1
        $x_1_2 = "Ckpgauidqzkhpinyep" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dofoil_AU_329333_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.AU"
        threat_id = "329333"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Routes Installation" wide //weight: 2
        $x_2_2 = "search_hyperfs_213" wide //weight: 2
        $x_2_3 = "yanwang" wide //weight: 2
        $x_1_4 = "fixtool.exe" wide //weight: 1
        $x_1_5 = "SbieDll.dll" wide //weight: 1
        $x_1_6 = "VirtualBox" wide //weight: 1
        $x_1_7 = "bearvpn3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Dofoil_AU_329333_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dofoil.AU"
        threat_id = "329333"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://iplogger.org/1Ushp7" wide //weight: 1
        $x_1_2 = "https://iplogger.org/1nGUi7" wide //weight: 1
        $x_1_3 = "http://195.161.68.58/1.exe" wide //weight: 1
        $x_1_4 = "Games of the chrome" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

