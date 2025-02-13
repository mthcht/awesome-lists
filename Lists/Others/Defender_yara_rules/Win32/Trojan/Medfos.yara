rule Trojan_Win32_Medfos_A_2147655194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Medfos.A"
        threat_id = "2147655194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Medfos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 e0 69 (c6 45|e9 c6 45) (c6 45|e9 c6 45)}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 30 00 00 (68 00 b0|e9 68 00 b0)}  //weight: 1, accuracy: Low
        $x_1_3 = {69 ff c8 00 00 00 (57|e9) (a2 ?? ?? ?? ??|e9 a2 ?? ?? ?? ??) (ff 15|e9)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Medfos_A_2147655194_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Medfos.A"
        threat_id = "2147655194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Medfos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 5c 39 48 (32 d8|e9) (88|e9 88) (42|e9) (fe c0|e9) (83|e9 83)}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 f3 70 (c6 45|e9 c6 45) (c6 45|e9 c6 45)}  //weight: 1, accuracy: Low
        $x_1_3 = {69 c0 e8 03 00 00 (a3 ?? ?? ?? ??|e9 a3 ?? ?? ?? ??) (c3|e9)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Medfos_B_2147655403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Medfos.B"
        threat_id = "2147655403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Medfos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 c7 45 e0 68 00 (66 c7 45 e2|e9 66 c7 45 e2) (66 c7 45 e4|e9 66 c7 45 e4)}  //weight: 10, accuracy: Low
        $x_1_2 = {81 fe 66 66 66 06 (89|e9 89)}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 66 66 66 06 (0f 86|e9)}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 66 66 66 06 (76|e9)}  //weight: 1, accuracy: Low
        $x_10_5 = {c7 45 f4 2e 00 00 00 (89|e9 (89|e9 89)) (6a 0a|e9 (6a 0a|e9)) (8d|e9 8d) (50|e9) (8b cb|e9 (8b cb|e9))}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Medfos_B_2147655403_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Medfos.B"
        threat_id = "2147655403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Medfos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 c7 45 ec 68 00 (66 c7 45 ee|e9 66 c7 45 ee) (66 c7 45 f0|e9 66 c7 45 f0)}  //weight: 10, accuracy: Low
        $x_1_2 = {81 fe 66 66 66 06 (89|e9 89)}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 66 66 66 06 (0f 86|e9)}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 66 66 66 06 (76|e9)}  //weight: 1, accuracy: Low
        $x_10_5 = {c7 45 fc 2e 00 00 00 (33 db|e9 (33 db|e9)) (6a 0a|e9 (6a 0a|e9)) (8d|e9 8d) (50|e9) (8b|e9 (8b|e9 8b))}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Medfos_T_2147662972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Medfos.T"
        threat_id = "2147662972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Medfos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {60 b8 01 00 00 00 [0-5] 0f a2 89 45 ec 89 55 ed}  //weight: 3, accuracy: Low
        $x_1_2 = {8a 80 e8 07 00 00 84 c0 5f 5e}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 fa 78 c6 45 fb 65 c6 45 fc 00 66 ab 33 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Medfos_V_2147665059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Medfos.V!dll"
        threat_id = "2147665059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Medfos"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {75 0a 68 2f 75 00 00 e9 86 00 00 00 b9 4b 00 00 00 33 c0 8d}  //weight: 2, accuracy: High
        $x_1_2 = {63 6f 6e 69 6d 65 2e 69 6e 66 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 55 70 64 61 74 61 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = "https//%s:%d/WinData%d.Dll?HELO-STX-2*%s*%s*%s$" ascii //weight: 1
        $x_1_5 = {5c 57 69 6e 44 61 74 61 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {31 31 31 2e 31 31 31 2e 31 31 31 2e 31 31 31 00}  //weight: 1, accuracy: High
        $x_1_7 = {2f 57 69 6e 44 61 74 61 25 64 2e 64 6c 6c 3f 44 41 54 41 2d 53 54 58 2d 32 2a 30 78 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Medfos_X_2147671593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Medfos.X"
        threat_id = "2147671593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Medfos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 02 02 00 00 (ff|e9 ff) (ff d7|e9) (5f|e9) (c3|e9)}  //weight: 1, accuracy: Low
        $x_1_2 = {68 02 02 00 00 (ff|e9 ff) (ff d7|e9) (ff 05 ?? ?? ?? ??|e9 ff 05 ?? ?? ?? ??) (ff|e9 ff)}  //weight: 1, accuracy: Low
        $x_10_3 = {0f b6 40 17 (50|e9) (ff|e9 ff) (ff|e9 ff) (ff 15|e9)}  //weight: 10, accuracy: Low
        $x_10_4 = {8d 44 30 02 (80|e9 80) ((0f 85 ?? ?? ?? ??|e9 0f 85 ?? ?? ?? ??)|(75 ??|e9 75 ??)) (03|e9 03)}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Medfos_AF_2147680404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Medfos.AF"
        threat_id = "2147680404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Medfos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 75 70 6c 6f 61 64 69 6e 67 2f 69 64 3d 25 64 26 75 3d}  //weight: 10, accuracy: High
        $x_10_2 = {00 00 5c 00 53 00 79 00 73 00 57 00 4f 00 57 00 36 00 34 00 5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_1_3 = {05 00 00 ff 16 89 45 06 00 8b 75 ?? 81 c6}  //weight: 1, accuracy: Low
        $x_1_4 = {05 00 00 ff 16 89 85 06 00 8b 75 ?? 81 c6}  //weight: 1, accuracy: Low
        $x_1_5 = {05 00 00 ff 16 89 45 09 00 8b b5 ?? ?? ?? ?? 81 c6}  //weight: 1, accuracy: Low
        $x_1_6 = {05 00 00 ff 16 89 85 09 00 8b b5 ?? ?? ?? ?? 81 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Medfos_AF_2147680404_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Medfos.AF"
        threat_id = "2147680404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Medfos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "221"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {00 75 70 6c 6f 61 64 69 6e 67 2f 69 64 3d 25 64 26 75 3d}  //weight: 100, accuracy: High
        $x_100_2 = {00 00 5c 00 53 00 79 00 73 00 57 00 4f 00 57 00 36 00 34 00 5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 100, accuracy: High
        $x_10_3 = "://%d.%d.%d.%d/" ascii //weight: 10
        $x_10_4 = {00 75 70 6c 6f 61 64 69 6e 67 2f 69 64 3d 25 64 26 6d 3d 25 64 26 6e 3d 25 64}  //weight: 10, accuracy: High
        $x_10_5 = {c7 45 fc 57 00 07 80}  //weight: 10, accuracy: High
        $x_1_6 = {81 c3 a4 05 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {81 c1 a4 05 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {81 c2 a4 05 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {81 c0 a4 05 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {81 c6 a4 05 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {81 c7 a4 05 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Medfos_AK_2147682013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Medfos.AK"
        threat_id = "2147682013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Medfos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 75 70 6c 6f 61 64 69 6e 67 2f 69 64 3d 25 64 26 75 3d}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 5c 00 53 00 79 00 73 00 57 00 4f 00 57 00 36 00 34 00 5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "://%d.%d.%d.%d/" ascii //weight: 1
        $x_1_4 = "%s%08lX%08lX.dll" wide //weight: 1
        $x_1_5 = {68 e7 8a d3 2c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

