rule Trojan_Win32_Tapaoux_A_2147630215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tapaoux.A"
        threat_id = "2147630215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tapaoux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c7 8a 0e 99 f7 7c 24 10 8a 54 14 14 3a ca 74 02 32 ca 88 0c 33 47 46 3b fd 7c e4}  //weight: 1, accuracy: High
        $x_1_2 = {64 a1 30 00 00 00 0f b6 40 68 83 e0 70 85 c0 74 07}  //weight: 1, accuracy: High
        $x_1_3 = {50 6c 61 79 53 50 5f 64 6c 6c 2e 64 6c 6c 00 4d 65 6d 6f 72 79 41 6c 6c 6f 63 45 72 72 6f 72 00}  //weight: 1, accuracy: High
        $x_1_4 = "%s\\%s.dll" ascii //weight: 1
        $x_1_5 = "%s\\%s.sys" ascii //weight: 1
        $x_1_6 = "%s\\%s.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Tapaoux_B_2147651157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tapaoux.B"
        threat_id = "2147651157"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tapaoux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 8a 0e 99 f7 7c 24 10 8a 54 14 14 3a ca 74 02 32 ca 88 0c 33 47 46 3b fd 7c e4}  //weight: 1, accuracy: High
        $x_1_2 = {8b c7 99 f7 7c 24 10 8b c1 25 ff 00 00 00 8a 54 14 14 0f be ea 3b c5 74 02 32 ca}  //weight: 1, accuracy: High
        $x_1_3 = {8b 6f 3c 03 ef 8b ?? 50 8b ?? 34}  //weight: 1, accuracy: Low
        $x_1_4 = {68 1a 4c 72 0a 12 0b 48 04 25 19 5c 1b 0b 4e 4a}  //weight: 1, accuracy: High
        $x_1_5 = {3d 69 0d 15 4f 41 41 54 5a 7c 47 51 47 5a 53 42}  //weight: 1, accuracy: High
        $x_1_6 = {54 b8 11 11 11 11 ff d0 90 90 90 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Tapaoux_C_2147651206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tapaoux.C"
        threat_id = "2147651206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tapaoux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exe.s%s%" ascii //weight: 1
        $x_1_2 = "LMTHlortnoC*** --!<" ascii //weight: 1
        $x_1_3 = {80 7c 24 1b 44 0f 84 40 01 00 00 6a 01 83 c7 04 6a 00 57 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tapaoux_L_2147690021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tapaoux.L"
        threat_id = "2147690021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tapaoux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 0a 99 59 f7 f9 69 d2 e8 03 00 00 52 ff d3 6a 02 58 39 45 88 75 0e 89 75 88 89}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 ec 35 c6 45 ed 62 c6 45 ee 62 c6 45 ef 5f c6 45 f0 62 c6 45 f1 10 c6 45 f2 33 c6 45 f3 5f c6 45 f4 54 c6 45 f5 55 c6 45 f6 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {76 0b 80 44 05 ec 10 40 3b 45 e8 72 f5 39 75 7c 76 31 57}  //weight: 1, accuracy: High
        $x_1_4 = {53 53 ff d7 89 44 24 24 39 5c 24 1c 74 20 39 5c 24 20 74 1a 3b c3 74 16 8b}  //weight: 1, accuracy: High
        $x_1_5 = {c6 45 fc 51 c6 45 fd 52 c6 45 fe 00 e8 ?? ?? ?? ?? 89 45 f0 83 c4 14 33 c0 39 75 f0 7e 0b 80 44 05 f4 13 40 3b 45 f0 7c f5 39 75 e8 7e 29 89 5d ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

