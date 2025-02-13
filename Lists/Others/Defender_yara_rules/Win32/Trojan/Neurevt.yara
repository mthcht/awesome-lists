rule Trojan_Win32_Neurevt_A_2147679945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neurevt.A"
        threat_id = "2147679945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neurevt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 b8 11 11 11 11 c6 00 40 c6 40 01 41 c6 40 02 42 c6 40 03 43 c6 40 04 44 c6 40 05 45 c6 40 06 46 33 c0 50 50 50 68 22 22 22 22 50 50 b8 33 33 33 33 ff d0}  //weight: 1, accuracy: High
        $x_1_2 = "%d|%s|%s|%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neurevt_B_2147685422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neurevt.B"
        threat_id = "2147685422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neurevt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e6 9c 18 ee c7 45 ?? c8 8a 25 1d c7 45 ?? 00 02 ab 7f c7 45 ?? 10 00 05 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {11 8a f8 82 c7 45 ?? 9b 1c 37 d2 c7 45 ?? aa d8 9b 4d c7 45 ?? 64 b9 cc c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Neurevt_A_2147685718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neurevt.gen!A"
        threat_id = "2147685718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neurevt"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_50_1 = {6e 65 75 72 65 76 74 00}  //weight: 50, accuracy: High
        $x_50_2 = {57 69 6e 37 7a 69 70 00 00 00 00 55 75 69 64 00}  //weight: 50, accuracy: High
        $x_50_3 = {69 00 6e 00 73 00 00 00 64 00 62 00 67 00 00 00 72 00 6f 00 6e 00 00 00}  //weight: 50, accuracy: High
        $x_50_4 = "Betabot (c) 2012-2014, coded by Userbase" wide //weight: 50
        $x_1_5 = {69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 00 00 00 00 73 00 74 00 65 00 61 00 6d 00 2e 00 65 00 78 00 65 00 00 00 73 00 6b 00 79 00 70 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {2e 00 69 00 6e 00 69 00 00 00 00 00 2e 00 73 00 79 00 73 00 00 00 00 00 25 00 73 00 5c 00 25 00 30 00 38 00 78 00 2e 00 6c 00 6e 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {42 00 49 00 54 00 53 00 00 00 00 00 4d 00 70 00 73 00 53 00 76 00 63 00 00 00 00 00 53 00 68 00 61 00 72 00 65 00 64 00 41 00 63 00 63 00 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 00 00 00 00 4d 00 70 00 43 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 64 00 6c 00 6c 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {57 44 53 74 61 74 75 73 00 00 00 00 57 44 45 6e 61 62 6c 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_1_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neurevt_C_2147689100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neurevt.C"
        threat_id = "2147689100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neurevt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 45 f0 e6 9c 18 ee c7 45 f4 c8 8a 25 1d c7 45 f8 00 02 ab 7f c7 45 fc 10 00 05 ff}  //weight: 2, accuracy: High
        $x_1_2 = {64 a1 30 00 00 00 53 56 85 c0 74 ?? 80 78 02 01 74}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 4d fc 30 0c 18 40 3b c7 72 f5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neurevt_F_2147711710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neurevt.F"
        threat_id = "2147711710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neurevt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4D5A90000300000004000000FFFF0000B8" wide //weight: 1
        $x_1_2 = "C:\\~tmp1315\\" wide //weight: 1
        $x_1_3 = "QCDRunMode.Connection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neurevt_A_2147727223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neurevt.gen!A!!Neurevt"
        threat_id = "2147727223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neurevt"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Neurevt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_50_1 = {6e 65 75 72 65 76 74 00}  //weight: 50, accuracy: High
        $x_50_2 = {57 69 6e 37 7a 69 70 00 00 00 00 55 75 69 64 00}  //weight: 50, accuracy: High
        $x_50_3 = {69 00 6e 00 73 00 00 00 64 00 62 00 67 00 00 00 72 00 6f 00 6e 00 00 00}  //weight: 50, accuracy: High
        $x_50_4 = "Betabot (c) 2012-2014, coded by Userbase" wide //weight: 50
        $x_1_5 = {69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 00 00 00 00 73 00 74 00 65 00 61 00 6d 00 2e 00 65 00 78 00 65 00 00 00 73 00 6b 00 79 00 70 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {2e 00 69 00 6e 00 69 00 00 00 00 00 2e 00 73 00 79 00 73 00 00 00 00 00 25 00 73 00 5c 00 25 00 30 00 38 00 78 00 2e 00 6c 00 6e 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {42 00 49 00 54 00 53 00 00 00 00 00 4d 00 70 00 73 00 53 00 76 00 63 00 00 00 00 00 53 00 68 00 61 00 72 00 65 00 64 00 41 00 63 00 63 00 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 00 00 00 00 4d 00 70 00 43 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 64 00 6c 00 6c 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {57 44 53 74 61 74 75 73 00 00 00 00 57 44 45 6e 61 62 6c 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_1_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

