rule Trojan_Win32_Redosdru_B_2147617425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.B"
        threat_id = "2147617425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "GH0STC" ascii //weight: 10
        $x_10_2 = "%s%s%s" ascii //weight: 10
        $x_10_3 = "%s\\%x.dll" wide //weight: 10
        $x_10_4 = {00 49 6e 73 74 61 6c 6c 00}  //weight: 10, accuracy: High
        $x_10_5 = "\\Release\\Loader.pdb" ascii //weight: 10
        $x_1_6 = "OpenProcessToken" ascii //weight: 1
        $x_1_7 = "GetTokenInformation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redosdru_B_2147617425_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.B"
        threat_id = "2147617425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 5
        $x_5_2 = {00 00 47 68 30 73 74 20 55 70 64 61 74 65 00 00}  //weight: 5, accuracy: High
        $x_1_3 = "%s\\%d_res.tmp" ascii //weight: 1
        $x_1_4 = "RegQueryValueEx(Svchost\\netsvcs)" ascii //weight: 1
        $x_1_5 = {41 64 64 41 63 63 65 73 73 41 6c 6c 6f 77 65 64 41 63 65 45 78 00 00 00 5c 44 72 69 76 65 72 73}  //weight: 1, accuracy: High
        $x_1_6 = {49 6e 73 74 61 6c 6c 4d 6f 64 75 6c 65 00 00 00 4d 69 63 72 6f 73 6f 66 74 20 44 65 76 69 63 65 20 4d 61 6e 61 67 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redosdru_C_2147617430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.C"
        threat_id = "2147617430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 54 24 04 8a 1c 11 80 c3 ?? 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 ?? 88 1c 11 41 3b c8 7c e1}  //weight: 5, accuracy: Low
        $x_5_2 = {6a 02 6a 00 68 00 fc ff ff 56 ff 15}  //weight: 5, accuracy: High
        $x_1_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 74 20 2f 69 6d [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {71 6d 67 72 2e 64 6c 6c 00 5c 44 72 69 76 65 72 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redosdru_C_2147617430_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.C"
        threat_id = "2147617430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 54 24 04 8a 1c 11 80 c3 ?? 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 ?? 88 1c 11 41 3b c8 7c e1}  //weight: 5, accuracy: Low
        $x_5_2 = {6a 02 6a 00 68 00 fc ff ff 56 ff 15}  //weight: 5, accuracy: High
        $x_2_3 = {6a 7c 53 e8 ?? ?? 00 00 8b f0 83 c4 08 85 f6 0f 84 ?? ?? 00 00 83 c3 06 c6 06 00}  //weight: 2, accuracy: Low
        $x_1_4 = {3d 00 00 20 03 73 0d 6a 02 6a 00 6a 00 53 ff 15}  //weight: 1, accuracy: High
        $x_1_5 = {8a 14 01 80 f2 ?? 88 10 40 4d 75 f4}  //weight: 1, accuracy: Low
        $x_1_6 = "%s\\%d_res.tmp" ascii //weight: 1
        $x_1_7 = "Gh0st Update" ascii //weight: 1
        $x_1_8 = "%s\\%sex.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redosdru_D_2147617431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.D"
        threat_id = "2147617431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 11 8a 14 01 80 ea 08 80 f2 20 88 14 01 41 3b ce 7c ef}  //weight: 1, accuracy: High
        $x_1_2 = "e:\\job\\gh0st\\Release\\Loader.pdb" ascii //weight: 1
        $x_1_3 = "GH0STC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redosdru_E_2147617432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.E"
        threat_id = "2147617432"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 7c 56 e8 ?? ?? ?? 00 83 c4 08 85 c0 74 da}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cd 2b cf 8b ee 8a 14 01 80 f2 62 88 10 40 83 ed 01 75 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redosdru_E_2147617432_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.E"
        threat_id = "2147617432"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "e:\\job\\gh0st\\Release\\Loader.pdb" ascii //weight: 1
        $x_1_2 = {8d 0c ad 00 00 00 00 b8 56 55 55 55 f7 e9 8b 47 04 8b ca c1 e9 1f 8d 54 0a 04 52 6a 08 50 ff 15 ?? ?? 40 00 8b f0 89 47 0c 85 f6 75 08}  //weight: 1, accuracy: Low
        $x_1_3 = {7e 11 8a 14 01 80 ea 08 80 f2 20 88 14 01 41 3b ce 7c ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redosdru_F_2147621855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.F"
        threat_id = "2147621855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 02 6a 00 68 08 fa ff ff 56 ff 15}  //weight: 2, accuracy: High
        $x_2_2 = {63 c6 44 24 ?? 62 c6 44 24 ?? 31 c6 44 24 ?? 73}  //weight: 2, accuracy: Low
        $x_2_3 = {3d 00 00 20 03 73 0d 6a 02 6a 00 6a 00 53 ff 15}  //weight: 2, accuracy: High
        $x_1_4 = {8b cd 8b ef 2b ce 8a 14 01 80 f2 ?? 88 10 40 4d 75 f4}  //weight: 1, accuracy: Low
        $x_1_5 = "[%02d/%02d/%d %02d:%02d:%02d] (%s)" ascii //weight: 1
        $x_1_6 = {00 25 73 5c 25 64 5f 72 65 [0-1] 2e 74 6d 70 00}  //weight: 1, accuracy: Low
        $x_1_7 = {00 52 65 67 51 75 65 72 79 56 61 6c 75 65 45 78 28 53 76 63 68 6f 73 74 5c 6e 65 74 73 76 63 73 29 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redosdru_L_2147630026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.L"
        threat_id = "2147630026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {48 c6 44 24 ?? 41 c6 44 24 ?? 43 c6 44 24 ?? 4b 8b 54 24 ?? 8d 8e ?? 00 00 00 c6 86 ?? 00 00 00 00 c6 44 24 ?? 65 c6 44 24 ?? 72}  //weight: 4, accuracy: Low
        $x_2_2 = {8a 1c 11 80 ?? ?? 88 1c 11 8b ?? ?? ?? 8a 1c 11 80 ?? ?? 88 1c 11 41 3b c8 7c}  //weight: 2, accuracy: Low
        $x_2_3 = {81 f9 00 04 00 00 76 1d b9 00 01 00 00 33 c0 8d ba 11 01 00 00 f3 ab 8b 15 ?? ?? ?? ?? 89 02 8b 15 ?? ?? ?? ?? 81 c2 11 01 00 00}  //weight: 2, accuracy: Low
        $x_2_4 = {8a 14 01 80 f2 ?? 88 10 40 4d 75}  //weight: 2, accuracy: Low
        $x_2_5 = {3d 00 00 20 03 73 0d 6a 02 6a 00 6a 00 53 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redosdru_2147630931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru"
        threat_id = "2147630931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 32 32 2e 31 38 36 2e [0-3] 2e [0-3] 3a [0-4] 2f 34 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_2 = {32 32 32 2e 31 38 36 2e 33 30 2e 31 38 36 3a [0-4] 2f 34 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_5_3 = {49 6e 74 65 72 6e 65 74 52 65 61 64 [0-16] 49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c [0-16] 49 6e 74 65 72 6e 65 74 4f 70 65 6e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redosdru_N_2147631817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.N"
        threat_id = "2147631817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Borland\\Delphi\\Locales" wide //weight: 10
        $x_10_2 = "OnlineKeylogger" wide //weight: 10
        $x_5_3 = "*.torrent" wide //weight: 5
        $x_5_4 = "[CLIPBOARD END]" wide //weight: 5
        $x_2_5 = "synsecurity.net/scripts" wide //weight: 2
        $x_1_6 = "avgcc.exe" wide //weight: 1
        $x_1_7 = "bdss.exe" wide //weight: 1
        $x_1_8 = "avp.exe" wide //weight: 1
        $x_1_9 = "nod32krn.exe" wide //weight: 1
        $x_1_10 = "bdagent.exe" wide //weight: 1
        $x_1_11 = "mcshield.exe" wide //weight: 1
        $x_1_12 = "pavfires.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redosdru_O_2147633038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.O"
        threat_id = "2147633038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {47 c6 44 24 ?? 68 c6 44 24 ?? 30 c6 44 24 ?? 73 8b 54 24 ?? 8d 8e ?? ?? 00 00 89 86 ?? ?? 00 00 b0 74}  //weight: 2, accuracy: Low
        $x_1_2 = "CVideoCap" wide //weight: 1
        $x_1_3 = "Global\\mouse %d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redosdru_M_2147640644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.M"
        threat_id = "2147640644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 fc 80 04 11 ?? [0-16] 8b 55 fc 80 34 11 ?? [0-16] 41 3b c8 7c}  //weight: 2, accuracy: Low
        $x_1_2 = "PCRat Update" ascii //weight: 1
        $x_1_3 = {25 73 5c 64 6c 6c 63 61 63 68 65 5c 25 73 [0-5] 25 73 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_4 = "PCRatStact" ascii //weight: 1
        $x_1_5 = "%s\\%d_res.tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redosdru_Q_2147640929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.gen!Q"
        threat_id = "2147640929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {49 8b 4d fc 8a 1c 0a 80 f3 ?? 88 1c 0a 42 3b d0 7c d8}  //weight: 3, accuracy: Low
        $x_3_2 = {8b 4d fc 0f be 11 85 d2 74 21 8b 45 fc 8a 08 32 4d f8 8b 55 fc 88 0a 8b 45 f8 83 c0 01 89 45 f8}  //weight: 3, accuracy: High
        $x_2_3 = {6a 02 6a 00 68 00 fc ff ff 56 ff 15}  //weight: 2, accuracy: High
        $x_2_4 = {8a 47 01 c1 e6 06 3c 3d 8b de 75 1c 8b 75 fc}  //weight: 2, accuracy: High
        $x_2_5 = {8a 11 80 ea 86 8b 45 fc 03 45 f8 88 10 8b 4d fc 03 4d f8 8a 11 80 f2 87 8b 45 fc}  //weight: 2, accuracy: High
        $x_2_6 = {46 75 63 6b 59 6f 75 2e 74 78 74 00}  //weight: 2, accuracy: High
        $x_2_7 = {4e 6f 68 61 63 6b 65 72 2d 76 69 63 20 55 70 64 61 74 65 00}  //weight: 2, accuracy: High
        $x_2_8 = "ger.uoykcuF" ascii //weight: 2
        $x_1_9 = {4d 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 73 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_10 = {67 68 6f 73 74 20 55 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_11 = {46 75 63 6b 5f 61 76 70 00}  //weight: 1, accuracy: High
        $x_1_12 = {25 73 5c 77 69 25 64 6e 64 2e 74 65 6d 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redosdru_R_2147644064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.R"
        threat_id = "2147644064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 99 a1 01 00 57 56 ff}  //weight: 1, accuracy: High
        $x_1_2 = {52 5f 4f 5f 6f 5f 4f 5f 50 00}  //weight: 1, accuracy: High
        $x_2_3 = {8b 55 fc 8a 1c 11 80 f3 86 88 1c 11 8b 55 fc 8a 1c 11 80 c3 e7 88 1c 11 41 3b c8 7c}  //weight: 2, accuracy: High
        $x_1_4 = {b0 2f c6 45 f4 68 c6 45 f7 70 c6 45 f8 3a 88 45 f9 88 45 fa c6 45 fb 00}  //weight: 1, accuracy: High
        $x_1_5 = {b2 4f b1 4e b0 4d c6 45 e0 25 c6 45 e1 73 c6 45 e3 53 c6 45 e4 48}  //weight: 1, accuracy: High
        $x_1_6 = {61 73 66 61 66 73 61 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {30 5c 72 6f 73 73 65 63 6f 72 50 6c 61 72 74 6e 65 43 5c 6d 65 74 73 79 53 5c 4e 4f 49 54 50 49 52 43 53 45 44 5c 45 52 41 57 44 52 41 48 00}  //weight: 1, accuracy: High
        $x_1_8 = {73 79 73 74 65 6d 33 32 5c 7a 65 72 6f 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_9 = {47 6c 6f 62 61 6c 5c 66 79 74 20 25 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redosdru_S_2147646682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.S"
        threat_id = "2147646682"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 0e 8a 0c ?? 80 f1 ?? 88 0c ?? 40 3b ?? 7c f2}  //weight: 2, accuracy: Low
        $x_1_2 = {74 23 8a 8a ?? ?? ?? ?? bf ?? ?? ?? ?? 80 f1 ?? 33 c0 88 8a ?? ?? ?? ?? 83 c9 ff 42 f2 ae f7 d1 49 3b d1 72 dd}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 00 5c 26 05 99 f7 f9 b8 59 be 90 4a}  //weight: 1, accuracy: High
        $x_2_4 = "Flag:%s Name:%s IP:%s OS:%s" ascii //weight: 2
        $x_1_5 = "%sDay%sHour%sMin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redosdru_U_2147648735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.U"
        threat_id = "2147648735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 50 72 6f 67 72 61 7e 31 5c 25 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 25 5c [0-5] 2e 56 42 53}  //weight: 1, accuracy: Low
        $x_1_2 = {55 ff d7 50 ff d3 8b f8 56 ff 74 24 ?? ff d7 85 c0 74 ?? ff 74 24 ?? 8d 46 ?? 50 ff 15 ?? ?? ?? ?? 85 c0 75 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redosdru_V_2147688650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.V"
        threat_id = "2147688650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 41 02 83 c1 04 8d b0 ff fe fe 7e f7 d0 33 f0 f7 c6 00 01 01 81 74 e8}  //weight: 1, accuracy: High
        $x_1_2 = {66 81 38 4d 5a 57 74 08 ?? ?? ?? ?? ?? ?? ?? ?? 8b 78 3c 03 f8 89 7c 24 10 81 3f 50 45 00 00 74 08}  //weight: 1, accuracy: Low
        $x_5_3 = {8b 54 24 04 8a 1c 11 80 c3 7a 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 59 88 1c 11 41 3b c8 7c e1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redosdru_W_2147690919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.W"
        threat_id = "2147690919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 00 4d c6 45 01 5a 66 81 7d 00 4d 5a 74 07 5f 5e 5d}  //weight: 1, accuracy: High
        $x_1_2 = {c6 07 4d c6 47 01 5a ff d5 66 81 3f 4d 5a 74 08 5f 5e 5d}  //weight: 1, accuracy: High
        $x_2_3 = {81 ca 00 ff ff ff 42 8a 14 02 8a 1c 2f 32 da 8b 54 24 1c 88 1c 2f 47 3b fa 72 90 5d 5b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Redosdru_AA_2147691443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.AA"
        threat_id = "2147691443"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 e4 4d c6 45 e5 6f c6 45 e6 7a c6 45 e7 69 c6 45 e8 6c c6 45 e9 6c c6 45 ea 61 c6 45 eb 2f}  //weight: 1, accuracy: High
        $x_1_2 = {80 04 11 7a 03 ca 8b ?? ?? 80 34 11 59 03 ca 42 3b d0 7c e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redosdru_X_2147691980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.X"
        threat_id = "2147691980"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 1c 11 80 c3 7a 88 1c 11 8b 55 fc 8a 1c 11 80 f3 59 88 1c 11 41 3b c8}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 0c 4b c6 44 24 0d 6f c6 44 24 0e 74 c6 44 24 0f 68 c6 44 24 10 65}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 c9 59 c6 45 cb 54 c6 45 cc 45 c6 45 cd 4d c6 45 ce 5c}  //weight: 1, accuracy: High
        $x_1_4 = {c6 44 24 24 53 c6 44 24 25 4f c6 44 24 26 46 c6 44 24 27 54}  //weight: 1, accuracy: High
        $x_1_5 = {c6 44 24 27 2f c6 44 24 28 34 c6 44 24 29 2e c6 44 24 2a 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Redosdru_AB_2147705500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.AB"
        threat_id = "2147705500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 11 0f be 45 f0 2b d0 8b 4d fc 03 4d f8 88 11 8b 55 fc 03 55 f8 0f be 02 0f be 4d ec 33 c1 8b 55 fc 03 55 f8 88 02 eb bf}  //weight: 1, accuracy: High
        $x_1_2 = {fb ff ff 4d c6 85 ?? fb ff ff 6f c6 85 ?? fb ff ff 7a c6 85 ?? fb ff ff 69 c6 85 ?? fb ff ff 6c c6 85 ?? fb ff ff 6c c6 85 ?? fb ff ff 61 c6 85 ?? fb ff ff 2f c6 85 ?? fb ff ff 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redosdru_Z_2147718222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.Z!bit"
        threat_id = "2147718222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fb ff ff 4d c6 85 ?? fb ff ff 6f c6 85 ?? fb ff ff 7a c6 85 ?? fb ff ff 69 c6 85 ?? fb ff ff 6c c6 85 ?? fb ff ff 6c c6 85 ?? fb ff ff 61 c6 85 ?? fb ff ff 2f c6 85 ?? fb ff ff 34}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 11 2b d0 8b 45 ec 03 45 e8 88 10 0f be 4d dc 8b 55 ec 03 55 e8 0f be 02 33 c1 8b 4d ec 03 4d e8 88 01 eb bf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redosdru_D_2147720486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.D!bit"
        threat_id = "2147720486"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 c1 f8 ?? 88 07 47 83 fb 02 7d ?? 8b c2 c1 f8 ?? 88 07 47 83 fb 01 7d ?? 88 17}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 0c 30 80 c1 ?? 80 f1 ?? 88 0c 30 40 3b c7 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 14 0b 30 10 8b 45 ?? 40 89 45 ?? 3b 45 ?? 72 9f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Redosdru_E_2147722532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.E!bit"
        threat_id = "2147722532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 11 0f be 45 f0 2b d0 8b 4d f4 03 4d fc 88 11 8b 55 f4 03 55 fc 0f be 02 0f be 4d ec 33 c1 8b 55 f4 03 55 fc 88 02 eb bf}  //weight: 1, accuracy: High
        $x_1_2 = {fe ff ff 47 c6 85 ?? fe ff ff 65 c6 85 ?? fe ff ff 74 c6 85 ?? fe ff ff 6f c6 85 ?? fe ff ff 6e c6 85 ?? fe ff ff 67 c6 85 ?? fe ff ff 35 c6 85 ?? fe ff ff 33 c6 85 ?? fe ff ff 38 c6 85 ?? fe ff ff 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 0a 32 08 8b 55 ?? 03 55 ?? 88 0a e9 0c 00 8b 55 ?? 03 55 ?? 8b 45 ?? 03 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redosdru_ARU_2147919739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redosdru.ARU!MTB"
        threat_id = "2147919739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redosdru"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 f8 83 c2 01 89 55 f8 8b 45 f8 3b 45 f4 7d 30 8b 4d fc 03 4d f8 0f be 11 0f be 45 f0 2b d0 8b 4d fc 03 4d f8 88 11 8b 55 fc 03 55 f8 0f be 02 0f be 4d ec 33 c1 8b 55 fc 03 55 f8 88 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

