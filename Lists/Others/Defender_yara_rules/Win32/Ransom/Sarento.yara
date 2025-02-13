rule Ransom_Win32_Sarento_A_2147697446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sarento.A"
        threat_id = "2147697446"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sarento"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "%svict?cust=%s&guid=%s" ascii //weight: 2
        $x_1_2 = ".to/vict?cust=" ascii //weight: 1
        $x_2_3 = "encryptor_raas_readme_liesmich.txt" ascii //weight: 2
        $x_2_4 = "The files on your computer have been securely encrypted by Encryptor RaaS." ascii //weight: 2
        $x_1_5 = "wallet.dat" ascii //weight: 1
        $x_1_6 = "Encryptor RaaS" ascii //weight: 1
        $x_2_7 = {81 7c 24 18 3e 1d 60 a2 75 ?? 81 7c 24 1c 17 cc 49 c1 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Sarento_B_2147706066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sarento.B"
        threat_id = "2147706066"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sarento"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $n_1_1 = "\\Bin\\a2hooks32.pdb" ascii //weight: -1
        $n_1_2 = "\\{A2IPC}" ascii //weight: -1
        $n_1_3 = "[a2hooks]" ascii //weight: -1
        $n_1_4 = "CicLoaderWndClass" ascii //weight: -1
        $n_1_5 = "Testing key \"%s\" value \"%s\"" ascii //weight: -1
        $n_1_6 = "name = %p - namelen = %d" ascii //weight: -1
        $x_1_7 = "wallet.dat" ascii //weight: 1
        $x_1_8 = "electrum.dat" ascii //weight: 1
        $x_1_9 = "/C vssadmin Delete Shadows /Quiet /All" ascii //weight: 1
        $x_1_10 = ";doc;docm;docx;dot;" ascii //weight: 1
        $x_1_11 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 [0-16] 52 00 61 00 61 00 53 00}  //weight: 1, accuracy: Low
        $x_1_12 = {45 6e 63 72 79 70 74 6f 72 [0-16] 52 61 61 53}  //weight: 1, accuracy: Low
        $x_2_13 = {76 00 69 63 74 00 3f 63 75 73 74 3d 00 26 67 75 69 64 3d 00}  //weight: 2, accuracy: High
        $x_2_14 = {65 00 6e 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 5f 00 72 00 61 00 61 00 73 00 [0-16] 2e 00 74 00 78 00 74 00}  //weight: 2, accuracy: Low
        $x_2_15 = {65 6e 63 72 79 70 74 6f 72 5f 72 61 61 73 [0-16] 2e 74 78 74}  //weight: 2, accuracy: Low
        $x_2_16 = {54 00 68 00 65 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 6f 00 6e 00 20 00 79 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 73 00 65 00 63 00 75 00 72 00 65 00 6c 00 79 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 [0-16] 52 00 61 00 61 00 53 00 2e 00}  //weight: 2, accuracy: Low
        $x_2_17 = {54 68 65 20 66 69 6c 65 73 20 6f 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 76 65 20 62 65 65 6e 20 73 65 63 75 72 65 6c 79 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 45 6e 63 72 79 70 74 6f 72 [0-16] 52 61 61 53 2e}  //weight: 2, accuracy: Low
        $x_3_18 = "://decryptoraveidf7.onion.cab" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Sarento_C_2147706288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sarento.C"
        threat_id = "2147706288"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sarento"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vict?cust=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sarento_C_2147706288_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sarento.C"
        threat_id = "2147706288"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sarento"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 72 2b 62 00 77 62 00 [0-96] 53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36}  //weight: 1, accuracy: Low
        $x_1_2 = {73 74 3d 00 26 67 75 69 64 3d 00 [0-64] 53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36}  //weight: 1, accuracy: Low
        $x_1_3 = {00 53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36 00 [0-16] 53 68 65 6c 6c 45 78 65 63 75 74 65 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Sarento_C_2147706288_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sarento.C"
        threat_id = "2147706288"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sarento"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 44 24 10 c7 44 24 0c 19 01 02 00 c7 44 24 08 00 00 00 00 [0-16] c7 04 24 02 00 00 80 (e8|ff 15) ?? ?? ?? 00 83 ec 14 85 c0}  //weight: 10, accuracy: Low
        $x_10_2 = {77 00 61 00 6c 00 6c 00 65 00 74 00 00 00 5c 00 00 00 2a 00 00 00 5c 00 2a 00 00 00 2e 00 2e 00 00 00 2e 00 00 00 20 00 3a 00 5c 00 00 00}  //weight: 10, accuracy: High
        $x_1_3 = {00 72 2b 62 00 77 62 00 [0-96] 53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36}  //weight: 1, accuracy: Low
        $x_1_4 = {73 74 3d 00 26 67 75 69 64 3d 00 [0-64] 53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36}  //weight: 1, accuracy: Low
        $x_1_5 = {00 53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36 00 [0-16] 53 68 65 6c 6c 45 78 65 63 75 74 65 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Sarento_DA_2147890401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sarento.DA!MTB"
        threat_id = "2147890401"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sarento"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Encryptor RaaS Decryptor" ascii //weight: 1
        $x_1_2 = "This file is supposed to another system!" ascii //weight: 1
        $x_1_3 = "Your system may not be connected to the internet." ascii //weight: 1
        $x_1_4 = "wallet" wide //weight: 1
        $x_1_5 = "FindNextFileW" ascii //weight: 1
        $x_1_6 = "SetEndOfFile" ascii //weight: 1
        $x_1_7 = "WriteFile" ascii //weight: 1
        $x_1_8 = "DeleteFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

