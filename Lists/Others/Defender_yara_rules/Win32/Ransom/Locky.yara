rule Ransom_Win32_Locky_A_2147709170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.A"
        threat_id = "2147709170"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {24 fc 89 0c 24 8b 4d 08 8d 64 24 fc 33 0c 24 8b}  //weight: 1, accuracy: High
        $x_1_2 = {83 ec 04 89 0c 24 8b 4d 08 83 ec 04 33 0c 24 8b ff}  //weight: 1, accuracy: High
        $x_1_3 = {f4 69 63 6b 43 c7 45 f8 6f 75 6e 74 ff 15 0c 01}  //weight: 1, accuracy: High
        $x_1_4 = {d8 8d 36 b9 00 00 00 00 f7 d8 f7 d8 8d 36 83 c9}  //weight: 1, accuracy: High
        $x_1_5 = {d8 f7 d8 8d 36 6a ff 83 c9 ff f7 d8 f7 d8 8d 36}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Locky_A_2147709170_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.A"
        threat_id = "2147709170"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 67 65 74 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_2 = {26 70 61 74 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_3 = {6f 70 74 33 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_4 = {26 6c 65 6e 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_5 = {34 46 73 52 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_6 = {34 44 69 73 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 73 74 61 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_8 = {26 61 63 74 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_9 = {26 65 6e 63 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_10 = {26 6c 61 6e 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_11 = {2f 31 2e 31 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_2_12 = {52 53 41 31 06 00 c7 85}  //weight: 2, accuracy: Low
        $x_1_13 = "83.217.8.61" ascii //weight: 1
        $x_1_14 = "31.202.130.9" ascii //weight: 1
        $x_1_15 = "91.234.35.106" ascii //weight: 1
        $x_2_16 = "/checkupdate" ascii //weight: 2
        $x_2_17 = {ef bb bf 3d 24 7c 24 3d 2d 3d 2e 7e 0d 0a 20 20 20 20 20 20 20 20 20 20 20 20 21 21 21 20 49 4d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Locky_A_2147710450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.A!!Locky.gen!A"
        threat_id = "2147710450"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "Locky: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 67 65 74 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_2 = {26 70 61 74 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_3 = {6f 70 74 33 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_4 = {26 6c 65 6e 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_5 = {34 46 73 52 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_6 = {34 44 69 73 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 73 74 61 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_8 = {26 61 63 74 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_9 = {26 65 6e 63 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_10 = {26 6c 61 6e 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_11 = {2f 31 2e 31 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_2_12 = {52 53 41 31 06 00 c7 85}  //weight: 2, accuracy: Low
        $x_1_13 = "83.217.8.61" ascii //weight: 1
        $x_1_14 = "31.202.130.9" ascii //weight: 1
        $x_1_15 = "91.234.35.106" ascii //weight: 1
        $x_2_16 = "/checkupdate" ascii //weight: 2
        $x_2_17 = {ef bb bf 3d 24 7c 24 3d 2d 3d 2e 7e 0d 0a 20 20 20 20 20 20 20 20 20 20 20 20 21 21 21 20 49 4d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Locky_A_2147710450_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.A!!Locky.gen!A"
        threat_id = "2147710450"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "Locky: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "locky" ascii //weight: 1
        $x_1_2 = ".ms11 (Security copy)" ascii //weight: 1
        $x_1_3 = "wallet.dat" ascii //weight: 1
        $x_1_4 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_5 = ".djvu" ascii //weight: 1
        $x_1_6 = "/submit.php" ascii //weight: 1
        $x_1_7 = "&act=getkey&affid=" ascii //weight: 1
        $x_1_8 = "&act=gettext&lang=" ascii //weight: 1
        $x_1_9 = "&act=stats&path=" ascii //weight: 1
        $x_1_10 = {00 26 73 65 72 76 3d 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 26 63 6f 72 70 3d 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 26 65 6e 63 72 79 70 74 65 64 3d 00}  //weight: 1, accuracy: High
        $x_1_13 = {5f 4c 6f 63 6b 79 5f 72 65 63 6f 76 65 72 5f 69 6e 73 74 72 75 63 74 69 6f 6e 73 2e 62 6d 70 00}  //weight: 1, accuracy: High
        $x_1_14 = {6f 70 74 33 32 31 00}  //weight: 1, accuracy: High
        $x_1_15 = {6e 5f 48 45 4c 50 5f 69 6e 73 74 72 75 63 74 69 6f 6e 73 2e 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_16 = {2e 7a 65 70 74 6f 00}  //weight: 1, accuracy: High
        $x_1_17 = {81 c6 ef 6d 45 4e 81 d7 f5 9d 74 58}  //weight: 1, accuracy: High
        $x_1_18 = {80 3b b8 75 f4 80 7b 03 00 75 ee 80 7b 04 00 75 e8}  //weight: 1, accuracy: High
        $x_2_19 = {66 c7 03 90 e9 ff 75 fc 57 53 ff d6}  //weight: 2, accuracy: High
        $x_1_20 = {81 7d 10 e9 fd 00 00 75 17 80 3b ef 75 12 80 7b 01 bb 75 0c 80 7b 02 bf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Locky_B_2147711935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.B"
        threat_id = "2147711935"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 bc 8b 4d bc 81 c9 aa 02 67 64 6a 68 58 33 d2 f7 f1 89 45 b8 b8 71 4b 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a 07 58 2b 45 a0 89 45 9c 8b 4d 08 81 c9 e4 69 a7 89 8b 45 9c 33 d2 f7 f1 89 55 98 8b 45 98 25 2c 22 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8d 6d 00 83 c9 40 54 8f 45 84 51 83 f1 40 81 c1 da 0d 00 00 8a d2 51 ff b5 60 ff ff ff 52 5a c7 85 60 ff ff ff be e8 3b 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_A_2147712210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.gen!A"
        threat_id = "2147712210"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {69 c0 e1 24 19 b1 c1 ?? 07}  //weight: 10, accuracy: Low
        $x_1_2 = {26 6f 73 3d 00 00 00 00 26 73 65 72 76 3d 00 00 26 63 6f 72 70 3d 00 00 26 6c 61 6e 67 3d 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {26 61 63 74 3d 67 65 74 6b 65 79 26 61 66 66 69 64 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {72 75 00 00 [0-3] 69 6e 66 6f 00 [0-3] 62 69 7a 00}  //weight: 1, accuracy: Low
        $x_1_5 = {73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 3a 00 5a 00 6f 00 6e 00 65 00 2e 00 49 00 64 00 65 00 6e 00 74 00 69 00 66 00 69 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {2e 00 44 00 4f 00 43 00 00 00 00 00 2e 00 70 00 65 00 6d 00 00 00 00 00 2e 00 70 00 31 00 32 00 00 00 00 00 2e 00 63 00 73 00 72 00 00 00 00 00 2e 00 63 00 72 00 74 00 00 00 00 00 2e 00 6b 00 65 00 79 00 00 00 00 00 77 00 61 00 6c 00 6c 00 65 00 74 00 2e 00 64 00 61 00 74 00 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Locky_C_2147716318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.C!!Locky.gen!C"
        threat_id = "2147716318"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "Locky: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "C: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "locky" ascii //weight: 1
        $x_1_2 = ".ms11 (Security copy)" ascii //weight: 1
        $x_1_3 = "wallet.dat" ascii //weight: 1
        $x_1_4 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_5 = ".djvu" ascii //weight: 1
        $x_1_6 = "/submit.php" ascii //weight: 1
        $x_1_7 = "&act=getkey&affid=" ascii //weight: 1
        $x_1_8 = "&act=gettext&lang=" ascii //weight: 1
        $x_1_9 = "&act=stats&path=" ascii //weight: 1
        $x_1_10 = {00 26 73 65 72 76 3d 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 26 63 6f 72 70 3d 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 26 65 6e 63 72 79 70 74 65 64 3d 00}  //weight: 1, accuracy: High
        $x_1_13 = {5f 4c 6f 63 6b 79 5f 72 65 63 6f 76 65 72 5f 69 6e 73 74 72 75 63 74 69 6f 6e 73 2e 62 6d 70 00}  //weight: 1, accuracy: High
        $x_1_14 = {6f 70 74 33 32 31 00}  //weight: 1, accuracy: High
        $x_1_15 = {6e 5f 48 45 4c 50 5f 69 6e 73 74 72 75 63 74 69 6f 6e 73 2e 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_16 = {2e 7a 65 70 74 6f 00}  //weight: 1, accuracy: High
        $x_1_17 = {81 c6 ef 6d 45 4e 81 d7 f5 9d 74 58}  //weight: 1, accuracy: High
        $x_1_18 = {80 3b b8 75 f4 80 7b 03 00 75 ee 80 7b 04 00 75 e8}  //weight: 1, accuracy: High
        $x_2_19 = {66 c7 03 90 e9 ff 75 fc 57 53 ff d6}  //weight: 2, accuracy: High
        $x_1_20 = {81 7d 10 e9 fd 00 00 75 17 80 3b ef 75 12 80 7b 01 bb 75 0c 80 7b 02 bf}  //weight: 1, accuracy: High
        $n_50_21 = {53 00 70 00 79 00 48 00 75 00 6e 00 74 00 65 00 72 00 [0-2] 5f 00 43 00 72 00 61 00 73 00 68 00 2e 00 6c 00 6f 00 67 00}  //weight: -50, accuracy: Low
        $n_50_22 = {53 00 70 00 79 00 48 00 75 00 6e 00 74 00 65 00 72 00 20 00 [0-2] 3a 00 20 00 41 00 64 00 76 00 61 00 6e 00 63 00 65 00 64 00 20 00 4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 20 00 52 00 65 00 6d 00 6f 00 76 00 61 00 6c 00}  //weight: -50, accuracy: Low
        $n_50_23 = {53 00 70 00 79 00 48 00 75 00 6e 00 74 00 65 00 72 00 20 00 [0-2] 20 00 2d 00 20 00 22 00 4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 53 00 75 00 69 00 74 00 65 00 22 00}  //weight: -50, accuracy: Low
        $n_50_24 = {53 00 70 00 79 00 48 00 75 00 6e 00 74 00 65 00 72 00 [0-2] 5f 00 6d 00 75 00 74 00 45 00 58 00}  //weight: -50, accuracy: Low
        $n_50_25 = "SpyHunter has experienced a crash." wide //weight: -50
        $n_50_26 = "\\EnigmaSoftwareGroup\\RegHunter\\RegHunterConfig" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Locky_D_2147717219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.D"
        threat_id = "2147717219"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {73 65 74 75 70 61 70 69 2e 64 6c 6c 00 71 77 65 72 74 79 00}  //weight: 10, accuracy: High
        $x_10_2 = "CryptImportKey" ascii //weight: 10
        $x_10_3 = "DsRoleGetPrimaryDomainInformation" ascii //weight: 10
        $x_10_4 = {8b 41 08 8d 50 ff}  //weight: 10, accuracy: High
        $x_10_5 = {b9 00 08 00 00 8d 46 20 c6 00 00 40 49 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_H_2147725164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.H!bit"
        threat_id = "2147725164"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "lmuawtwgeqpfsm" ascii //weight: 1
        $x_1_2 = "CmMoveMemory" ascii //weight: 1
        $x_1_3 = {83 ec 04 c6 04 24 0a 8d 35 ?? ?? ?? ?? 81 ee 21 e3 64 98 56 8d 35 ?? ?? ?? ?? 81 ee 21 e3 64 98 56 e8 ?? ?? ?? ?? 83 f8 00 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_I_2147733274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.I"
        threat_id = "2147733274"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_Locky_recover_instructions.txt" wide //weight: 1
        $x_1_2 = "Delete Shadows /Quiet /All" wide //weight: 1
        $x_1_3 = "wallet.dat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_PA_2147741468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.PA!MTB"
        threat_id = "2147741468"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 d0 33 c9 83 e9 01 23 4d ?? 03 c1 32 d2 fe ca 32 55 ?? f6 d2 8b f8 89 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 32 45 ?? 88 07 32 45 ?? 80 37 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 00 02 45 ?? 89 7d ?? 0f b6 c0 89 45 ?? 0f af d7 03 ca 89 0d ?? ?? ?? 00 8b 45 ?? 0b 45 ?? 33 45 ?? f7 d0 33 c9 83 e9 01 23 4d ?? 03 c1 32 d2 fe ca 32 55 ?? f6 d2 8b f8 89 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 32 45 ?? 88 07 32 45 ?? 80 37 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_RPX_2147850587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.RPX!MTB"
        threat_id = "2147850587"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d9 8b 4d ec 03 c2 8a 0c 01 32 cb 42 88 08 3b d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_RPX_2147850587_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.RPX!MTB"
        threat_id = "2147850587"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 54 24 0c 83 44 24 38 19 83 44 24 40 0a 8b c3 0f af 44 24 10 8d 34 c0 03 f2 03 f6 47 83 6c 24 20 01 75 8d}  //weight: 1, accuracy: High
        $x_1_2 = {8b 54 24 18 8b 7c 24 0c 8b c1 0f af c6 89 44 24 78 8d 84 3a f9 01 00 00 89 44 24 18 8b 44 24 14 0f af c1 03 c7 8d 34 db 03 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_DAS_2147851801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.DAS!MTB"
        threat_id = "2147851801"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {74 22 49 74 07 88 44 34 20 46 eb 4e 6a 0b 53 6a 07 59 e8 c5 fe ff ff 8b f8 59 59 85 ff 74 3b 57 6a 00 eb 27 6a 03 59 51 53 eb e7 8a 44 34 1f 6a 03 53 6a 02 59 88 44 24 18}  //weight: 2, accuracy: High
        $x_2_2 = {83 e4 f8 8b 45 14 66 0f 6e 45 18 66 0f 6e 55 10 83 a1 24 01 00 00 00 33 d2 42 66 0f 6e da 8b 55 0c 66 0f 6e c8 66 0f 62 d0 51 66 0f 62 d9 66 0f 62 da 66 0f 7f 59 10 8b 4d 08 e8 d8 fd ff ff 8b e5 5d c2 14}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_ALK_2147852047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.ALK!MTB"
        threat_id = "2147852047"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 6d 00 8a 0e 31 f6 31 f6 31 f6 30 cd 30 cd 30 cd 88 6d 00 8b 1c 24 43 89 1c 24 8b 1c 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_CCAB_2147889020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.CCAB!MTB"
        threat_id = "2147889020"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 6c 24 14 03 6c 24 08 8b 54 24 1c 03 54 24 04 8a 6d 00 8a 22 30 e5 88 6d 00 83 44 24 08 ?? ff 44 24 04 8b 5c 24 04 3b 5c 24 20 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_A_2147893035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.A!MTB"
        threat_id = "2147893035"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 0c 24 8b 4d 08 8d 64 24 fc 33 0c 24 8b ff 33 c0 31 0c 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_CCEL_2147897336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.CCEL!MTB"
        threat_id = "2147897336"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d ec 8b 95 ?? ?? ?? ?? a1 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? c1 e8 10 32 04 0a 8d 95 ?? ?? ?? ?? 52 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_CCFA_2147898587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.CCFA!MTB"
        threat_id = "2147898587"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 e4 fe ff ff 03 85 ?? fe ff ff 0f be 08 33 8d ?? fe ff ff 8b 95 ?? fe ff ff 03 95 ?? fe ff ff 88 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_GJU_2147904980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.GJU!MTB"
        threat_id = "2147904980"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {da f9 6d 9e c7 85 ?? ?? ?? ?? 57 4b 8c 88 c7 85 ?? ?? ?? ?? 57 4b 8c 88 c7 85 ?? ?? ?? ?? 19 c8 f1 26 c7 85 ?? ?? ?? ?? cb 47 57 0c}  //weight: 5, accuracy: Low
        $x_5_2 = "W0Cu3ahX4y" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_GJV_2147905015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.GJV!MTB"
        threat_id = "2147905015"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c2 33 d2 f7 f1 b9 ?? ?? ?? ?? 8b c7 25 00 30 00 00 83 ca 2a 2b ca 33 d2 f7 f6 8b c7 33 ca 81 c9 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c8 8d 87 ?? ?? ?? ?? 0f af c8 89 0d ?? ?? ?? ?? ff 45 f4 8b 45 e4 03 45 f4 03 45 0c 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_MKV_2147907031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.MKV!MTB"
        threat_id = "2147907031"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c1 33 d2 f7 75 b4 8a 45 fe 02 c0 02 45 ff 89 4d ec 88 45 fe 01 15 ?? ?? ?? ?? ff d3 8b 4d f4 83 f1 7f ba 5e 7d f3 2a 83 e0 13 2b d1 0b c2 01 05 ?? ?? ?? ?? 83 7d f4 00 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_GJW_2147907600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.GJW!MTB"
        threat_id = "2147907600"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 58 03 c1 54 8f 45 c4 32 d2 02 55 d4 56 8f 45 c0 89 45 e8 8b 7d e8 8b ff 8b 45 d8 33 45 dc 33 c2 f7 d0 8a ff 0a 05 ?? ?? ?? ?? 88 07 8b c6 69 c0 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b ce}  //weight: 10, accuracy: Low
        $x_1_2 = "Backup.ocx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_NL_2147911281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.NL!MTB"
        threat_id = "2147911281"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 65 f8 76 ff d6 25 ?? ?? ?? ?? 0f af 45 f8 2b f8 0f af 7d ?? 8b 45 08 2b c7 89 45 f0}  //weight: 3, accuracy: Low
        $x_3_2 = {33 d2 8b c7 f7 f1 0f b6 4d ?? 33 d2 2b c8 8b 45 ec}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_YBK_2147914533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.YBK!MTB"
        threat_id = "2147914533"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 2f 8a 16 31 f6 30 d5 88 2f 8b 5c 24 04 83 c3 02 89 5c 24 04 8b 1c 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_CCJD_2147916378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.CCJD!MTB"
        threat_id = "2147916378"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 a5 78 ff ff ff 00 c7 45 84 b2 c5 1f e6 c7 45 88 97 17 52 9a c7 85 70 ff ff ff 54 c8 30 e5 c7 85 7c ff ff ff 54 c8 30 e5 c7 45 80 26 d3 74 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_TOZ_2147937228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.TOZ!MTB"
        threat_id = "2147937228"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {be 2d 04 00 00 b8 39 02 00 00 8d bc 36 ?? ?? ?? ?? 2b c6 d1 e0 2b f8 03 cf 8b 7d 08 88 14 3b 8d 91 77 fd ff ff 85 d2 74}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_ZID_2147943832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.ZID!MTB"
        threat_id = "2147943832"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {d2 e8 d2 eb 24 01 80 e3 01 02 d8 0f b6 c3 0d 32 c1 2c 65 03 d0 8a 45 ff 80 e3 01 02 c0 0f b6 f3 02 c3 88 45 ff 8b ce 83 c9 19 8b c6 83 f0 2e 03 d1 03 d0 83 7d f8 00 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_VZV_2147958724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.VZV!MTB"
        threat_id = "2147958724"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d0 c1 c2 0d 2a ca 32 cb 88 0c 07 8a c8 80 e1 1f 0f b6 d3 d3 c2 8b 4d ?? d1 c9 03 d1 8b c8 c1 c9 17 81 c1 68 2f 70 53 33 d1 40 89 55 ec 3b 46 10 72}  //weight: 5, accuracy: Low
        $x_1_2 = "_Locky_recover_instructions.txt" ascii //weight: 1
        $x_1_3 = ".locky" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Locky_MX_2147959502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Locky.MX!MTB"
        threat_id = "2147959502"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 83 c4 04 81 45 08 fb e5 d4 ff 21 75 dc 81 45 08 05 1a eb ff 33 fa c7 45 dc f0 01 40 00 3b f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

