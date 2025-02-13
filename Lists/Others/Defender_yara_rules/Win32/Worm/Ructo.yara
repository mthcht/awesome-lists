rule Worm_Win32_Ructo_B_2147641090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ructo.B"
        threat_id = "2147641090"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ructo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\tudo\\baixa" wide //weight: 1
        $x_1_2 = {00 00 76 00 6f 00 63 00 65 00 3d 00 00 00 10 00 00 00 45 00 6e 00 76 00 69 00 61 00 64 00 6f 00 3d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Ructo_G_2147644829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ructo.G"
        threat_id = "2147644829"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ructo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 55 00 73 00 65 00 72 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 [0-23] 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00}  //weight: 2, accuracy: Low
        $x_2_2 = {3a 00 5c 00 74 00 75 00 64 00 6f 00 5c 00 [0-16] 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00}  //weight: 2, accuracy: Low
        $x_1_3 = "regsvr32 /s /u" wide //weight: 1
        $x_1_4 = "@terra.com.br" wide //weight: 1
        $x_1_5 = "MAIL FROM:" wide //weight: 1
        $x_1_6 = "\\msmsgs.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Ructo_H_2147644883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ructo.H"
        threat_id = "2147644883"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ructo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Baixa\\Project1.vbp" wide //weight: 10
        $x_1_2 = "regsvr32 /s /u" wide //weight: 1
        $x_1_3 = "@terra.com.br" wide //weight: 1
        $x_1_4 = "MAIL FROM:" wide //weight: 1
        $x_1_5 = "\\msmsgs.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Ructo_J_2147648147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ructo.J"
        threat_id = "2147648147"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ructo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "projetorenovado" wide //weight: 1
        $x_1_2 = {44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 64 00 6f 00 72 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 [0-32] 5c 00 70 00 72 00 6f 00 6a 00 65 00 63 00 74 00 [0-4] 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = {66 69 64 65 70 75 74 61 72 75 69 6d 00}  //weight: 1, accuracy: High
        $x_1_4 = {76 65 72 69 66 69 63 61 61 72 71 75 69 76 6f 00}  //weight: 1, accuracy: High
        $x_1_5 = "regsvr32 /s /u" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_Ructo_J_2147648147_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ructo.J"
        threat_id = "2147648147"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ructo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 3a 50 45 00 00 0f 94 c0 f7 d8 50 e8 ?? ?? 00 00 c7 45 ?? 18 00 00 00 8b 8d ?? ?? ff ff 33 d2 66 81 ?? ?? 0b 01 0f 94 c2 f7 da 52 e8 ?? ?? 00 00 c7 45 ?? 19 00 00 00 c7 85 ?? ?? ff ff 00 00 00 00 c7 45 ?? 1a 00 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {81 bd 38 ff ff ff 50 45 00 00 0f 94 c0 f7 d8 50 e8 ?? ?? 00 00 33 c0 66 81 ?? ?? ?? ?? ?? 0b 01 0f 94 c0 f7 d8 50 e8 ?? ?? 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = "avgnsx.exe" wide //weight: 1
        $x_1_4 = "MsMpEng.exe" wide //weight: 1
        $x_1_5 = "msseces.exe" wide //weight: 1
        $x_1_6 = "Windir" wide //weight: 1
        $x_1_7 = "KeServiceDescriptorTable" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Ructo_M_2147648780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ructo.M"
        threat_id = "2147648780"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ructo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 73 57 65 62 43 6f 6e 6e 65 63 74 65 64 [0-5] 76 65 72 69 66 69 63 61 61 72 71 75 69 76 6f [0-5] 56 42 52 65 67 53 76 72 33 32 [0-5] 52 65 67 69 73 74 65 72 43 6f 6d 70 6f 6e 65 6e 74}  //weight: 2, accuracy: Low
        $x_2_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 [0-5] 43 72 79 70 74}  //weight: 2, accuracy: Low
        $x_1_3 = {6d 00 70 00 6c 00 61 00 79 00 65 00 72 00 32 00 [0-16] 2e 00 65 00 78 00 65 00 [0-10] 2e 00 73 00 63 00 72 00}  //weight: 1, accuracy: Low
        $x_1_4 = "regsvr32 /s /u" wide //weight: 1
        $x_1_5 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 [0-16] 52 00 65 00 67 00 52 00 65 00 61 00 64 00}  //weight: 1, accuracy: Low
        $x_2_6 = {2c 00 70 00 61 00 72 00 61 00 20 00 73 00 65 00 67 00 75 00 6e 00 64 00 6f 00 20 00 64 00 65 00 62 00 69 00 74 00 6f 00 20 00 6f 00 75 00 20 00 63 00 61 00 6e 00 63 00 65 00 6c 00 61 00 72 00 20 00 63 00 6c 00 69 00 63 00 6b 00 20 00 61 00 62 00 61 00 69 00 78 00 6f 00 2e 00 28 00 6f 00 62 00 73 00 2e 00 20 00 30 00 2c 00 39 00 38 00 20 00 2b 00 20 00 49 00 6d 00 70 00 6f 00 73 00 74 00 6f 00 73 00 29 00 [0-10] 3c 00 41 00 20 00 68 00 72 00 65 00 66 00 3d 00 [0-10] 3f 00 49 00 44 00 3d 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Ructo_P_2147651929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ructo.P"
        threat_id = "2147651929"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ructo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 05 80 00 eb 71 8b 13 8d 4d cc 51 56 52 ff 15 ?? ?? ?? ?? 8b d0 8d 4d dc ff d7 50 ff 15 ?? ?? ?? ?? 33 c9 66 3d 80 00}  //weight: 2, accuracy: Low
        $x_1_2 = "regsvr32 /s /u" wide //weight: 1
        $x_1_3 = "smtp.bra.terra.com.br" wide //weight: 1
        $x_1_4 = "PROCESSOR_ARCHITECTURE" wide //weight: 1
        $x_1_5 = "4.7.0.3001" wide //weight: 1
        $x_1_6 = {e1 00 f6 00 e7 00 f2 00 f3 00 f8 00 ae 00 e5 00 f8 00 e5}  //weight: 1, accuracy: High
        $x_1_7 = {cd 00 e5 00 f3 00 f3 00 e5 00 ee 00 e7 00 e5 00 f2 00 d0}  //weight: 1, accuracy: High
        $x_1_8 = {ed 00 f0 00 ec 00 e1 00 f9 00 e5 00 f2 00 b2 00}  //weight: 1, accuracy: High
        $x_1_9 = {ed 00 f3 00 e7 00 f3 00 e3 00 ae 00 e4 00 ec 00}  //weight: 1, accuracy: High
        $x_1_10 = {fa 00 e9 00 f0 00 bb 00 ae 00 f2 00 e1 00 f2 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Ructo_Q_2147655302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ructo.Q"
        threat_id = "2147655302"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ructo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 73 57 65 62 43 6f 6e 6e 65 63 74 65 64 [0-5] 76 65 72 69 66 69 63 61 61 72 71 75 69 76 6f [0-5] 56 42 52 65 67 53 76 72 33 32 [0-5] 52 65 67 69 73 74 65 72 43 6f 6d 70 6f 6e 65 6e 74}  //weight: 2, accuracy: Low
        $x_2_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 [0-5] 47 65 74 50 52 4f 47 52 41 4d 46 49 4c 45 53}  //weight: 2, accuracy: Low
        $x_2_3 = {4c 00 6f 00 77 00 52 00 69 00 73 00 6b 00 46 00 69 00 6c 00 65 00 54 00 79 00 70 00 65 00 73 00 [0-16] 2e 00 7a 00 69 00 70 00 3b 00 2e 00 72 00 61 00 72 00 3b 00 2e 00 6e 00 66 00 6f 00 3b 00 2e 00}  //weight: 2, accuracy: Low
        $x_1_4 = {53 00 61 00 76 00 65 00 5a 00 6f 00 6e 00 65 00 49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 [0-10] 52 00 45 00 47 00 5f 00 44 00 57 00 4f 00 52 00 44 00}  //weight: 1, accuracy: Low
        $x_1_5 = "mplayer2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

