rule TrojanSpy_Win32_Tougle_A_2147721786_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Tougle.A!bit"
        threat_id = "2147721786"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tougle"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 18 8a 04 0a 32 c3 88 44 16 fc 8b 0d ?? ?? ?? 00 8b 34 8d ?? ?? ?? 00 8a 44 16 fc 84 c0 74 03 42 eb b1}  //weight: 1, accuracy: Low
        $x_1_2 = {51 8b 44 24 08 80 38 6f 75 17 80 78 01 62 75 11 80 78 02 66 75 0b 80 78 03 3a 75 05 83 c0 04 59 c3}  //weight: 1, accuracy: High
        $x_1_3 = {c7 02 6b 65 72 6e c7 45 ?? 65 6c 33 32 c7 45 ?? 2e 64 6c 6c ff 55 00}  //weight: 1, accuracy: Low
        $x_1_4 = {72 00 65 00 6d 00 6f 00 76 00 65 00 [0-32] 2f 00 63 00 68 00 6b 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Tougle_C_2147722937_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Tougle.C!bit"
        threat_id = "2147722937"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tougle"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 07 33 d2 b9 0a 00 00 00 f7 f1 b8 cd cc cc cc 83 c3 01 80 c2 30 88 54 33 ff f7 27 c1 ea 03 85 d2 89 17 77 db}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 14 31 30 14 30 8a 14 30 30 14 31 8a 14 31 30 14 30 83 e9 01 83 c0 01 8b d1 2b d0 83 fa 01 7d de}  //weight: 1, accuracy: High
        $x_1_3 = {33 c0 89 07 89 47 04 6a 04 89 47 08 8d 54 24 20 53 89 47 0c 52 66 89 47 10 e8 ?? ?? ?? 00 6a 10 8d 43 04 50 57 e8 ?? ?? ?? 00 56 83 c3 14 53 55 e8 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 40 68 00 10 00 00 50 6a 00 ff 55 c0 85 c0 8b 5d c8 89 03 0f 84 df 00 00 00 0f b7 4e 06 85 c9 8b 56 54 7e 19 8d 77 14 8b f9 8b 0e 85 c9 74 06 3b ca 73 02 8b d1 83 c6 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Tougle_D_2147723004_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Tougle.D!bit"
        threat_id = "2147723004"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tougle"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 18 8a 04 0a 32 c3 88 44 16 fc 8b 0d ?? ?? ?? ?? 8b 34 8d ?? ?? ?? ?? 8a 44 16 fc 84 c0 74 03}  //weight: 1, accuracy: Low
        $x_1_2 = {51 8b 44 24 08 80 38 6f 75 17 80 78 01 62 75 11 80 78 02 66 75 0b 80 78 03 3a 75 05 83 c0 04 59 c3}  //weight: 1, accuracy: High
        $x_1_3 = {c7 02 6b 65 72 6e c7 45 38 65 6c 33 32 c7 45 3c 2e 64 6c 6c ff 55 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Tougle_G_2147723316_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Tougle.G!bit"
        threat_id = "2147723316"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tougle"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4c 24 10 84 c9 8a 0c 28 74 0c 8a 54 28 01 c0 e9 04 c0 e2 04 0a ca 88 4c 24 28 40 c7 44 24 18 00 00 00 00 8b 7c 24 10 8b 54 24 2c 81 e7 ff 00 00 00 2b d7 3b c2 0f 83 b9 02 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 02 6b 65 72 6e c7 45 38 65 6c 33 32 c7 45 3c 2e 64 6c 6c ff 55 00 89 45 54 eb 35}  //weight: 1, accuracy: High
        $x_1_3 = {6a 02 6a 00 6a 00 ff 15 ?? ?? ?? 00 8b f0 85 f6 74 36 6a 00 6a 00 6a 00 6a 00 8d 54 24 24 6a 00 52 6a 01 6a 02 6a 10 68 ff 01 0f 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 56 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_4 = {00 77 74 61 25 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 00 2f 00 63 00 68 00 6b 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Tougle_L_2147726083_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Tougle.L!bit"
        threat_id = "2147726083"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tougle"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 04 19 32 c1 42 83 fa 10 88 04 19 75 02 33 d2 41 3b cd 72 e7}  //weight: 2, accuracy: High
        $x_2_2 = {c7 02 6b 65 72 6e c7 45 ?? 65 6c 33 32 c7 45 ?? 2e 64 6c 6c ff 55 00}  //weight: 2, accuracy: Low
        $x_2_3 = {c7 02 6b 65 72 6e c7 45 38 65 6c 33 32 c7 45 3c 2e 64 6c 6c ff 55 00 89 45 54 eb 35}  //weight: 2, accuracy: High
        $x_1_4 = {00 00 2f 00 63 00 68 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "schtasks /create /tn" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Tougle_N_2147729798_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Tougle.N!bit"
        threat_id = "2147729798"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tougle"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 07 83 c7 04 e2 f9}  //weight: 1, accuracy: High
        $x_1_2 = {76 19 8a 4c 35 ?? 32 0c 02 32 ca 46 83 fe 10 88 0c 02 75 02 33 f6 42 3b d3 72 e7}  //weight: 1, accuracy: Low
        $x_1_3 = {76 22 8b 55 ?? 8b 4e 04 8b 7d 08 03 c8 8b 12 8a 0c 39 03 d0 40 88 0c 1a 8b 0e 3b c1 72 e4}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 06 47 65 74 57 89 5d ?? c7 45 ?? 77 54 68 72 c7 45 ?? 65 61 64 50 c7 45 ?? 72 6f 63 65 c7 45 ?? 73 73 49 64 ff 55}  //weight: 1, accuracy: Low
        $x_1_5 = "schtasks /create /tn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

