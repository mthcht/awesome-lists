rule Backdoor_Win32_Ixeshe_H_2147717370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ixeshe.H!dha"
        threat_id = "2147717370"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ixeshe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 d1 0f 6b 9f d9 49 fc [0-80] 4d 69 63 72 6f 73 6f 66 74 20 45 6e 68 61 6e 63 65 64 20 43 72 79 70 74 6f 67 72 61 70 68 69 63 20 50 72 6f 76 69 64 65 72 20 76 31 2e 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Ixeshe_F_2147724230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ixeshe.F!dha"
        threat_id = "2147724230"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ixeshe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 57 c6 85 ?? ?? ?? ?? 32 c6 85 ?? ?? ?? ?? 31 c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? 2e}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 2f c6 85 ?? ?? ?? ?? 79 c6 85 ?? ?? ?? ?? 6d c6 85 ?? ?? ?? ?? 2f c6 85 ?? ?? ?? ?? 41 c6 85 ?? ?? ?? ?? 74 c6 85 ?? ?? ?? ?? 74}  //weight: 1, accuracy: Low
        $x_1_3 = {54 c6 85 99 ef ff ff 44 c6 85 9a ef ff ff 4f c6 85 9b ef ff ff 57 c6 85 9c ef ff ff 4e c6 85 9d ef ff ff 0d c6 85 9e ef ff ff 0a}  //weight: 1, accuracy: High
        $x_1_4 = {6b c6 85 45 ef ff ff 4b c6 85 46 ef ff ff 49 c6 85 47 ef ff ff 4c c6 85 48 ef ff ff 4c c6 85 49 ef ff ff 20 c6 85 4a ef ff ff 25 c6 85 4b ef ff ff 73 c6 85 4c ef ff ff 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Ixeshe_A_2147724231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ixeshe.A!dha"
        threat_id = "2147724231"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ixeshe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 bc 4d c6 45 bd 41 c6 45 be 49 c6 45 bf 4c c6 45 c0 5f}  //weight: 1, accuracy: High
        $x_1_2 = {35 65 37 65 38 31 30 30 00 00 00 00 25 73 00 00 25 77 73 00 25 78 00}  //weight: 1, accuracy: High
        $x_1_3 = {8a 1c 03 30 1c 2f 8b 5c 24 24 47 3b fb 0f 82}  //weight: 1, accuracy: High
        $x_1_4 = {b9 08 00 00 00 b8 ae ae ae ae 8d [0-9] f3 ab}  //weight: 1, accuracy: Low
        $x_1_5 = {b9 e1 04 00 00 33 c0 8d bd ?? ?? ff ff f3 ab 66 ab aa c6 85 ?? ?? ff ff 27 c6 85 ?? ?? ff ff 25 c6 85 ?? ?? ff ff 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Ixeshe_D_2147724232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ixeshe.D!dha"
        threat_id = "2147724232"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ixeshe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f c6 44 24 ?? 41 c6 44 24 ?? 4c c6 44 24 ?? 49 c6 44 24 ?? 56 c6 44 24 ?? 45}  //weight: 1, accuracy: Low
        $x_1_2 = {80 c2 41 50 c6 44 24 ?? 52 c6 44 24 ?? 45 c6 44 24 ?? 4d c6 44 24 ?? 4f}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 08 00 00 00 b8 cc cc cc cc 8d [0-6] 6a 00 f3 ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Ixeshe_B_2147724233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ixeshe.B!dha"
        threat_id = "2147724233"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ixeshe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 76 20 22 41 64 6f 62 65 20 41 73 73 69 73 74 61 6e 74 22 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 22 25 73 22 20 2f 66 00 5c 73 79 73 74 65 6d 33 32 00 00 00 5c 61 63 72 6f 74 72 79 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "<form id=\"gaia_loginform\"" ascii //weight: 1
        $x_1_3 = {89 65 d8 68 74 ea 43 00 e8 ?? ?? ?? ?? 8d 45 b8 50 8b cf c6 45 fc 09 e8 ?? ?? ?? ?? 8b c8 e8 ?? ?? ?? ?? 50 8d 4d f0 c6 45 fc 0c e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Ixeshe_C_2147724234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ixeshe.C!dha"
        threat_id = "2147724234"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ixeshe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 44 24 1c c7 44 24 1c 00 00 00 00 50 68 7f 66 04 40 55 e8 ?? ?? ?? ?? 85 c0 75 24 8b 4c 24 18 8b 44 24 1c 81 e1 ff ff 00 00 3b c1 73 0b 6a 32}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 54 24 1c c7 44 24 14 01 00 00 00 33 f6 8d 44 24 14 50 68 c7 00 00 00 52 55 ff d7 8b 44 24 14 03 f0 81 fe d0 07 00 00 8d 54 04 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Ixeshe_E_2147724235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ixeshe.E!dha"
        threat_id = "2147724235"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ixeshe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 3a 5c 5c 4d 69 63 72 6f 73 6f 66 74 20 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 00 3a 00 5c 00 5c 00 2a 00 2e 00 6c 00 6e 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 04 5f 8a 0e 8a 56 01 46 83 6d 0c 03 46 8a 1e 46 88 5d 0a}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 e4 2f 50 8d 45 e4 ff 75 08 c6 45 ?? 46 c6 45 ?? 50 c6 45 ?? 4b 50 8d 85 ?? ?? ?? ?? 50 c6 45 ?? 25 c6 45 ?? 64 c6 45 ?? 2e c6 45 ?? 6a c6 45 ?? 73 c6 45 ?? 70 c6 45 ?? 3f c6 45 ?? 25 c6 45 ?? 73 88 5d}  //weight: 1, accuracy: Low
        $x_1_5 = {35 65 37 65 38 31 30 30 00 00 00 00 25 73 00 00 25 77 73 00 25 78 00}  //weight: 1, accuracy: High
        $x_1_6 = {b9 e1 04 00 00 33 c0 8d bd ?? ?? ff ff f3 ab 66 ab aa c6 85 ?? ?? ff ff 27 c6 85 ?? ?? ff ff 25 c6 85 ?? ?? ff ff 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

