rule Virus_Win32_Hipak_A_2147601624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Hipak.A"
        threat_id = "2147601624"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Hipak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "117"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {55 8b ec 6a ff 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02 5f 57 ff 15 ?? ?? ?? ?? 59 83 0d ?? ?? ?? ?? ff 83 0d ?? ?? ?? ?? ff ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 a1 ?? ?? ?? ?? 8b 00 a3 ?? ?? ?? ?? e8 f4 01 00 00 39 1d ?? ?? ?? ?? 75 0c 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 59 e8 c0 01 00 00 68}  //weight: 100, accuracy: Low
        $x_10_2 = {5f 49 6e 73 74 61 6c 6c 46 69 6c 74 65 72 40 38 00 00 00 00 68 00 6b 00 61 00 70 00 69 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 00 00 2f 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 00 00 00 00 00 00 00 00 6f 70 65 6e 00 00 00 00 2f 61 75 74 6f 72 75 6e 00 00 00 00 66 69 72 65 77 61 6c 6c 00 00 00 00 02 00 00 00 2e 72 65 6c 6f 63 00 00 5c 00 00 00 2a 2e 2a 00 61 3a 5c 00 53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 00 2d 00 00 00 2e 65 78 65}  //weight: 10, accuracy: High
        $x_1_3 = "MapViewOfFile" ascii //weight: 1
        $x_1_4 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_5 = "GetSystemDirectoryA" ascii //weight: 1
        $x_1_6 = "CreateThread" ascii //weight: 1
        $x_1_7 = "SeShutdownPrivilege" ascii //weight: 1
        $x_1_8 = "WS2_32.dll" ascii //weight: 1
        $x_1_9 = "MFC42u.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Hipak_B_2147601632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Hipak.B"
        threat_id = "2147601632"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Hipak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 70 65 6e 00 00 00 00 2f 61 75 74 6f 72 75 6e 00 00 00 00 6b 73 63 76 00 00 00 00 49 6e 65 74 49 6e 66 6f 00 00 00 00 30 34 00 00 2e 72 65 6c 6f 63 00 00 5c 00 00 00 2a 2e 2a 00 61 3a 5c 00 53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 00 2d 00 00 00 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 00 00 00 00 6d 6d 63 2e 65 78 65 00 72 65 67 65 64 69 74 2e 65 78 65 00 5c 72 65 67 65 64 69 74 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {43 72 65 61 74 65 54 68 72 65 61 64 00 00 24 01 47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 41 00 00 7d 01 47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 00 00 59 01 47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 00 40 01 47 65 74 50 72 6f 63 65 73 73 48 65 61 70 00 00 75 01 47 65 74 56 65 72 73 69 6f 6e 45 78 41 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 6c 6f 73 65 48 61 6e 64 6c 65 00 df 02 57 72 69 74 65 46 69 6c 65 00 d6 01 4d 61 70 56 69 65 77 4f 66 46 69 6c 65 00 35 00 43 72 65 61 74 65 46 69 6c 65 4d 61 70 70 69 6e 67 41 00 00 12 01 47 65 74 46 69 6c 65 53 69 7a 65 00 34 00 43 72 65 61 74 65 46 69 6c 65 41 00 68 02 53 65 74 46 69 6c 65 41 74 74 72 69 62 75 74 65 73 41 00 00 4b 45 52 4e 45 4c 33 32 2e 64 6c 6c 00 00 34 00 43 6c 6f 73 65 53 65 72 76 69 63 65 48 61 6e 64 6c 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Hipak_C_2147605898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Hipak.C"
        threat_id = "2147605898"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Hipak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 84 0d 58 f2 ff ff 5c 41 c6 84 0d 58 f2 ff ff 64 41 c6 84 0d 58 f2 ff ff 72 41 c6 84 0d 58 f2 ff ff 69 41 c6 84 0d 58 f2 ff ff 76 41 c6 84 0d 58 f2 ff ff 65 41 c6 84 0d 58 f2 ff ff 72 41 88 9c 0d 58 f2 ff ff 41 c6 84 0d 58 f2 ff ff 5c 41 88 9c 0d 58 f2 ff ff 41 c6 84 0d 58 f2 ff ff 76 41 c6 84 0d 58 f2 ff ff 63 41 c6 84 0d 58 f2 ff ff 68 41 c6 84 0d 58 f2 ff ff 6f 41 88 9c 0d 58 f2 ff ff 41 c6 84 0d 58 f2 ff ff 74 41 c6 84 0d 58 f2 ff ff 2e 41 c6 84 0d 58 f2 ff ff 65 41 c6 84 0d 58 f2 ff ff 78 41 c6 84 0d}  //weight: 1, accuracy: High
        $x_1_2 = {58 f2 ff ff 65 41 c6 84 0d 58 f2 ff ff 20 41 c6 84 0d 58 f2 ff ff 2f 41 c6 84 0d 58 f2 ff ff 61 41 8d bd 58 f2 ff ff 8d 95 fc fe ff ff c6 84 0d 58 f2 ff ff 75 41 c6 84 0d 58 f2 ff ff 74 41 c6 84 0d 58 f2 ff ff 6f 41 c6 84 0d 58 f2 ff ff 72 41 c6 84 0d 58 f2 ff ff 75 41 c6 84 0d 58 f2 ff ff 6e}  //weight: 1, accuracy: High
        $x_1_3 = {6f 70 65 6e 00 00 00 00 2f 61 75 74 6f 72 75 6e 00 00 00 00 6b 73 63 76 00 00 00 00 49 6e 65 74 49 6e 66 6f 00 00 00 00 30 34 00 00 2e 72 65 6c 6f 63 00 00 5c 00 00 00 2a 2e 2a 00 61 3a 5c 00 53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 00 2d 00 00 00 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Virus_Win32_Hipak_C_2147605898_1
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Hipak.C"
        threat_id = "2147605898"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Hipak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02 5f 57 ff 15 ?? ?? ?? ?? 59 83 0d ?? ?? ?? ?? ff 83 0d ?? ?? ?? ?? ff ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 a1 ?? ?? ?? ?? 8b 00 a3 ?? ?? ?? ?? e8 f4 01 00 00 39 1d ?? ?? ?? ?? 75 0c 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 59 e8 c0 01 00 00 68}  //weight: 1, accuracy: Low
        $x_1_2 = {b1 6d b2 30 b0 68 88 9d ec ?? ?? ?? c6 85 ed ?? ?? ?? 79 88 9d ee ?? ?? ?? c6 85 ef ?? ?? ?? 74 c6 85 f0 ?? ?? ?? 65}  //weight: 1, accuracy: Low
        $x_2_3 = {5f 49 6e 73 74 61 6c 6c 46 69 6c 74 65 72 40 38 00 [0-32] 2e 00 64 00 6c 00 6c 00 [0-16] 2f 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 00 00 00 00 00 00 00 00 6f 70 65 6e 00 00 00 00 2f 61 75 74 6f 72 75 6e 00 [0-64] 00 2e 72 65 6c 6f 63 00 00 5c 00 00 00 2a 2e 2a 00 61 3a 5c 00 53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 00 2d 00 00 00 2e 65 78 65}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Hipak_A_2147697465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Hipak.gen!A"
        threat_id = "2147697465"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Hipak"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 12 12 00 00 3b c7 89 45 f0 74 03 ff 55 f0 8b 4d f4 5f 5e 33 c0}  //weight: 1, accuracy: High
        $x_1_2 = {41 6a 01 68 00 00 00 80 c6 81 ?? ?? ?? ?? 70 41 88 81 ?? ?? ?? ?? 41 88 81 ?? ?? ?? ?? 41 c6 81 ?? ?? ?? ?? 6c 41 88 99 ?? ?? ?? ?? 41 c6 81 ?? ?? ?? ?? 76 41 c6 81 ?? ?? ?? ?? 2e 41 c6 81 ?? ?? ?? ?? 65 41 c6 81 ?? ?? ?? ?? 78 41 c6 81 ?? ?? ?? ?? 65}  //weight: 1, accuracy: Low
        $x_1_3 = {66 c7 44 44 58 73 00 40 66 c7 44 44 58 63 00 40 66 c7 44 44 58 61 00 40 66 c7 44 44 58 6e 00 40 66 c7 44 44 58 69 00 40 66 c7 44 44 58 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

