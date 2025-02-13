rule Backdoor_Win32_Venik_A_2147647064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venik.A"
        threat_id = "2147647064"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 0c 50 68 04 00 00 98 57 c7 44 ?? 2c 01 00 00 00 c7 44 24 ?? e8 03 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 fe 00 00 00 25 ff 00 00 00 56 99 f7 f9 8b 74 24 ?? fe c2 85 f6 76 ?? 8b 44 24 ?? 8a 08 32 ca 02 ca 88 08}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 50 41 58 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 50 41 44 ?? ?? ?? ?? 52 65 67 53 65 74 56 61 6c 75 65 45 78 28 53 65 72 76 69 63 65 44 6c 6c 29}  //weight: 1, accuracy: Low
        $x_1_4 = "%SystemRoot%\\System32\\svchost.exe -k krnlsrvc" ascii //weight: 1
        $x_1_5 = "Provides support for media palyer. This service can't be stoped." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Venik_D_2147682010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venik.D"
        threat_id = "2147682010"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 28 53 76 63 68 6f 73 74 5c 6b 72 6e 6c 73 72 76 63 29 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6b 72 6e 6c 73 72 76 63 00}  //weight: 1, accuracy: High
        $x_1_3 = {57 69 6e 64 6f 77 73 20 48 65 6c 70 20 53 79 73 74 65 6d 20 66 6f 72 20 58 33 32 20 77 69 6e 64 6f 77 73 20 64 65 73 6b 74 6f 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 69 6e 48 65 6c 70 33 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Venik_CnC_2147690744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venik!CnC"
        threat_id = "2147690744"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d 16 00 00 20 0f 87 07 01 00 00 0f 84 cc 00 00 00 3d 12 00 00 20 77 7d 74 65 3d 06 00 00 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Venik_F_2147691047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venik.F"
        threat_id = "2147691047"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8a 14 01 80 ea ?? 80 f2 ?? 88 14 01 41 3b [0-4] 7c}  //weight: 3, accuracy: Low
        $x_1_2 = {fe ff ff 53 c6 85 ?? fe ff ff 65 c6 85 ?? fe ff ff 72 c6 85 ?? fe ff ff 76 c6 85 ?? fe ff ff 69 c6 85 ?? fe ff ff 63 c6 85 ?? fe ff ff 65 c6 85 ?? fe ff ff 73 c6 85 ?? fe ff ff 5c c6 85 ?? fe ff ff 25 c6 85 ?? fe ff ff 73 88 9d ?? fe ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 81 c2 90 fe ff ff 51 81 c3 70 01 00 00 52 53 56 ff 15}  //weight: 1, accuracy: High
        $x_3_4 = {00 4c 6f 61 64 46 72 6f 6d 4d 65 6d 6f 72 79 20 45 4e 44 2d 2d 2d 0d 0a 00}  //weight: 3, accuracy: High
        $x_3_5 = {00 68 6d 50 72 6f 78 79 21 3d 20 4e 55 4c 4c 0d 0a 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Venik_G_2147693443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venik.G"
        threat_id = "2147693443"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 80 ea ?? 80 f2 ?? 88 14 01 41 3b [0-4] 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {fe ff ff 53 c6 85 ?? fe ff ff 65 c6 85 ?? fe ff ff 72 c6 85 ?? fe ff ff 76 c6 85 ?? fe ff ff 69 c6 85 ?? fe ff ff 63 c6 85 ?? fe ff ff 65 c6 85 ?? fe ff ff 73 c6 85 ?? fe ff ff 5c c6 85 ?? fe ff ff 25 c6 85 ?? fe ff ff 73 88 9d ?? fe ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {49 6e 73 74 61 6c 6c 54 69 6d 65 00 25 34 64 2d 25 2e 32 64 2d 25 2e 32 64 20 25 2e 32 64 3a 25 2e 32 64 00 25 64 2a 25 73 4d 48 7a 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 65 63 75 72 69 74 79 00 00 00 00 41 70 70 6c 69 63 61 74 69 6f 6e 00 70 75 6f 72 47 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Venik_G_2147693443_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venik.G"
        threat_id = "2147693443"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 74 24 0c 33 c9 85 f6 7e 11 8a 14 01 80 ea 7a 80 f2 19 88 14 01 41 3b ce 7c ef 5e c3}  //weight: 2, accuracy: High
        $x_1_2 = {68 10 27 00 00 e8 ?? ?? ?? ?? 50 8d 84 24 ?? ?? ?? ?? 8d 4c 24 ?? 50 8d 94 24 ?? ?? ?? ?? 51 52 c6 84 24 ?? ?? ?? ?? 00 c6 44 24 ?? 25 c6 44 24 ?? 73 c6 44 24 ?? 25 c6 44 24 ?? 64 c6 44 24 ?? 2e c6 44 24 ?? 76 c6 44 24 ?? 62 c6 44 24 ?? 73 c6 44 24 ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 c6 44 24 ?? 75 c6 44 24 ?? 65 c6 44 24 ?? 74 c6 44 24 ?? 56 c6 44 24 ?? 65 c6 44 24 ?? 73 c6 44 24 ?? 69 88 5c 24 ?? c6 44 24 ?? 52 c6 44 24 ?? 75 c6 44 24 ?? 00}  //weight: 1, accuracy: Low
        $x_2_4 = {00 4c 6f 61 64 46 72 6f 6d 4d 65 6d 6f 72 79 20 45 4e 44 2d 2d 2d 0d 0a 00}  //weight: 2, accuracy: High
        $x_2_5 = {00 68 6d 50 72 6f 78 79 21 3d 20 4e 55 4c 4c 0d 0a 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Venik_H_2147694851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venik.H"
        threat_id = "2147694851"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 ff 75 e8 ff d0 39 5d ec 74 0b 66 81 bd e4 fb ff ff 4d 5a 75 22 8d 45 e4 53 50 8d 85 e4 fb ff ff ff 75 f8 89 5d ec 50 ff 75 08 ff 15 ?? ?? ?? 10}  //weight: 1, accuracy: Low
        $x_1_2 = {4b 78 65 74 72 61 79 2e 65 78 65 00 33 36 30 74 72 61 79 2e 65 78 65 00 25 73 36 74 25 2e 33 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 68 6d 50 72 6f 78 79 21 3d 20 4e 55 4c 4c 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 4c 6f 61 64 46 72 6f 6d 4d 65 6d 6f 72 79 20 45 4e 44 2d 2d 2d 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_5 = {63 6d 64 2e 65 78 65 00 2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 31 20 26 26 20 64 65 6c 20 2f 66 2f 71 20 22 25 73 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Venik_I_2147696653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venik.I"
        threat_id = "2147696653"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "XGRyaXZlcnNcZXRjXGhvc3RzLmljcw==" ascii //weight: 1
        $x_1_2 = "U1lTVEVNXEN1cnJlbnRDb250cm9sU2V0XFNlcnZpY2VzXFJlbW90ZUFjY2Vzc1xSb3V0ZXJNYW5hZ2Vyc1xJcA==" ascii //weight: 1
        $x_1_3 = "U09GVFdBUkVcQWhuTGFiXFYzTGl0ZQ==" ascii //weight: 1
        $x_2_4 = {7c 73 65 61 72 63 68 2e 64 61 75 6d 2e 6e 65 74 7c 73 65 61 72 63 68 2e 6e 61 76 65 72 2e 63 6f 6d 7c 77 77 77 2e 6b 62 73 74 61 72 2e [0-64] 7c 77 77 77 2e 6b 6e 62 61 6e 6b 2e [0-64] 7c 6f 70 65 6e 62 61 6e 6b [0-64] 7c 77 77 77 2e 62 75 73 61 6e 62 61 6e 6b 2e [0-64] 7c}  //weight: 2, accuracy: Low
        $x_2_5 = "RegSetValueEx(Svchost\\krnlsrvc)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Venik_J_2147696654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venik.J"
        threat_id = "2147696654"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "121"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "ekimhuqcroanflvzgdjtxypswb" ascii //weight: 100
        $x_10_2 = "cmd.exe /c ping 127.0.0.1 -n 2&%s \"%s\"" ascii //weight: 10
        $x_10_3 = "RedTom21@HotMail.com" ascii //weight: 10
        $x_10_4 = {25 73 20 22 25 73 22 2c [0-16] 20 25 73 00 [0-3] 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 00 [0-3] 4d 5a 00 [0-3] 25 73 5c 25 73 2e 64 6c 6c 00 [0-3] 63 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 25 73 00 [0-3] 64 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 25 73 00 [0-3] 47 55 49}  //weight: 10, accuracy: Low
        $x_1_5 = {99 b9 1a 00 00 00 f7 f9 8b 45 08 03 45 f8 8a 4c 15 dc 88 08 eb}  //weight: 1, accuracy: High
        $x_1_6 = {99 b9 1a 00 00 00 f7 f9 46 3b f7 8a 54 14 10 88 54 1e ff 7c e9}  //weight: 1, accuracy: High
        $x_1_7 = {99 59 f7 f9 8b 4d 08 8a 44 15 e4 88 04 0e 46 3b f3 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Venik_K_2147696934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venik.K"
        threat_id = "2147696934"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 50 41 58 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 2e 50 41 44 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 4c 6f 61 64 46 72 6f 6d 4d 65 6d 6f 72 79 20 45 4e 44 2d 2d 2d 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 68 6d 50 72 6f 78 79 21 3d 20 4e 55 4c 4c 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 f0 53 c6 45 f1 59 c6 45 f2 53 c6 45 f3 54 c6 45 f4 45 c6 45 f5 4d c6 45 f6 5c c6 45 f7 53 c6 45 f8 65 c6 45 f9 74 c6 45 fa 75 c6 45 fb 70}  //weight: 1, accuracy: High
        $x_1_5 = {3c 2f 63 6f 64 65 3e 00 3c 63 6f 64 65 3e 00 00 47 45 54 20 2f 69 6e 64 65 78 2e 70 68 70 3f 69 70 3d 25 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Venik_L_2147696967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venik.L"
        threat_id = "2147696967"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 2c 69 c6 44 24 2d 63 c6 44 24 2e 65 c6 44 24 2f 44 c6 44 24 32 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {33 36 30 74 72 61 79 2e 65 78 65 00 25 73 36 74 25 2e 33 64 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_3 = {2e 48 4c 2e ff 7b 00 00 63 6d 64 2e 65 78 65 00 2f 63 20 70 69 6e 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Venik_G_2147709392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venik.G!bit"
        threat_id = "2147709392"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venik"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dnammoc\\nepo\\llehs\\exe.erolpxei\\snoitacilppA" ascii //weight: 1
        $x_1_2 = "%s%4d.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Venik_P_2147721525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venik.P!bit"
        threat_id = "2147721525"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venik"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {00 4c 6f 61 64 46 72 6f 6d 4d 65 6d 6f 72 79 20 45 4e 44 2d 2d 2d 0d 0a 00}  //weight: 3, accuracy: High
        $x_3_2 = {00 68 6d 50 72 6f 78 79 21 3d 20 4e 55 4c 4c 0d 0a 00}  //weight: 3, accuracy: High
        $x_1_3 = "\\System32\\svchost.exe -k" ascii //weight: 1
        $x_3_4 = {8b 55 08 03 55 fc 8a 02 2c ?? 8b 4d 08 03 4d fc 88 01 eb c9}  //weight: 3, accuracy: Low
        $x_1_5 = {fe ff ff 53 c6 85 ?? fe ff ff 65 c6 85 ?? fe ff ff 72 c6 85 ?? fe ff ff 76 c6 85 ?? fe ff ff 69 c6 85 ?? fe ff ff 63 c6 85 ?? fe ff ff 65 c6 85 ?? fe ff ff 73 c6 85 ?? fe ff ff 5c c6 85 ?? fe ff ff 25 c6 85 ?? fe ff ff 73 88 9d ?? fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Venik_R_2147722429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venik.R!bit"
        threat_id = "2147722429"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venik"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8a 14 01 80 ea ?? 80 f2 ?? 88 14 01 41 3b [0-4] 7c}  //weight: 3, accuracy: Low
        $x_1_2 = {fe ff ff 53 c6 85 ?? fe ff ff 65 c6 85 ?? fe ff ff 72 c6 85 ?? fe ff ff 76 c6 85 ?? fe ff ff 69 c6 85 ?? fe ff ff 63 c6 85 ?? fe ff ff 65 c6 85 ?? fe ff ff 73 c6 85 ?? fe ff ff 5c c6 85 ?? fe ff ff 25 c6 85 ?? fe ff ff 73 88 9d ?? fe ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 1
        $x_1_4 = "System32\\svchost.exe -k" ascii //weight: 1
        $x_1_5 = {3c 2f 63 6f 64 65 3e 00 3c 63 6f 64 65 3e 00 00 47 45 54 20 2f 69 6e 64 65 78 2e 70 68 70 3f 69 70 3d 25 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Venik_S_2147727200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venik.S!bit"
        threat_id = "2147727200"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venik"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8a 14 01 80 ea ?? 80 f2 ?? 88 14 01 41 3b [0-4] 7c}  //weight: 3, accuracy: Low
        $x_3_2 = {fe ff ff 53 c6 85 ?? fe ff ff 65 c6 85 ?? fe ff ff 72 c6 85 ?? fe ff ff 76 c6 85 ?? fe ff ff 69 c6 85 ?? fe ff ff 63 c6 85 ?? fe ff ff 65 c6 85 ?? fe ff ff 73 c6 85 ?? fe ff ff 5c c6 85 ?? fe ff ff 25 c6 85 ?? fe ff ff 73 88 9d ?? fe ff ff}  //weight: 3, accuracy: Low
        $x_3_3 = {3c 2f 63 6f 64 65 3e 00 3c 63 6f 64 65 3e 00 00 47 45 54 20 2f 69 6e 64 65 78 2e 70 68 70 3f 69 70 3d 25 73}  //weight: 3, accuracy: High
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 1
        $x_1_5 = {59 6f 77 21 20 42 61 64 20 68 6f 73 74 20 6c 6f 6f 6b 75 70 2e 00}  //weight: 1, accuracy: High
        $x_1_6 = {48 6f 73 74 20 6e 61 6d 65 20 69 73 3a 20 25 73 0a 00}  //weight: 1, accuracy: High
        $x_1_7 = {41 64 64 72 65 73 73 20 25 64 20 3a 20 25 73 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Venik_H_2147727861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venik.H!!Venik.H"
        threat_id = "2147727861"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venik"
        severity = "Critical"
        info = "Venik: an internal category used to refer to some threats"
        info = "H: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {49 6e 73 74 61 6c 6c 54 69 6d 65 00 25 34 64 2d 25 2e 32 64 2d 25 2e 32 64 20 25 2e 32 64 3a 25 2e 32 64}  //weight: 10, accuracy: High
        $x_10_2 = {25 63 25 63 25 63 25 63 25 63 25 63 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_3 = {43 6c 6f 73 65 50 72 6f 78 79 00}  //weight: 10, accuracy: High
        $x_10_4 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 00}  //weight: 10, accuracy: High
        $x_10_5 = "Applications\\iexplore.exe\\shell\\open\\command" ascii //weight: 10
        $x_10_6 = "NvsBackenss" ascii //weight: 10
        $x_20_7 = {8a 14 01 80 f2 19 80 c2 7a 88 14 01}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*))) or
            ((1 of ($x_20_*) and 4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Venik_B_2147734224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venik.B!dha"
        threat_id = "2147734224"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venik"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 0c 52 8d 44 24 1c 6a 0c 50 68 04 00 00 98 57 c7 44 24 ?? 01 00 00 00 c7 44 24 ?? e8 03 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {4b 69 6c 6c 20 59 6f 75 00 00 00 00 25 34 2e 32 20 6d 47 42 00 00 00 00 25 34 2e 32 20 66 4d 42 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 50 41 58 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 2e 50 41 44 00}  //weight: 1, accuracy: Low
        $x_1_4 = {25 73 5c 25 73 65 78 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Venik_E_2147734226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venik.E!dha"
        threat_id = "2147734226"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venik"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $n_1_1 = "cacls.exe c:\\" ascii //weight: -1
        $n_2_2 = "/search?hl=en&q" ascii //weight: -2
        $x_1_3 = "\\System32\\svchost.exe -k" ascii //weight: 1
        $x_1_4 = {00 49 6e 73 74 61 6c 6c 00 52 75 6e}  //weight: 1, accuracy: High
        $x_1_5 = {2e 50 41 58 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 2e 50 41 44 00}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 00 00 00 21 0f 87 ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? 05 00 00 00 e0 83}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 02 00 00 32 0f 87 ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? 3d 03 00 00 31}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 44 24 08 8a 08 32 ca 02 ca 88 08 40 4e 75 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

