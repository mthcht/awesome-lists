rule Ransom_Win32_Loktrom_A_2147649404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Loktrom.A"
        threat_id = "2147649404"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Loktrom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WebMoney" ascii //weight: 1
        $x_1_2 = "/f /im explorer.exe" ascii //weight: 1
        $x_1_3 = {b9 a0 00 00 00 ba 98 02 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {cf f0 e8 eb ee e6 e5 ed e8 e5 ec 20 4d 69 63 72 6f 73 6f 66 74 20 53 65 63 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Loktrom_C_2147667650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Loktrom.C"
        threat_id = "2147667650"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Loktrom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 db b8 07 00 00 00 3b d8 0f 8f ?? 00 00 00 b9 02 00 00 00 be 01 00 00 00 b8 42 01 00 00 3b f0 0f 8f ?? 00 00 00 83 fb 08}  //weight: 1, accuracy: Low
        $x_1_2 = "60E84E0000006B00650072006E0065006C003300320000006E00740064006C006C" wide //weight: 1
        $x_1_3 = "Neagato_Hotela.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Loktrom_B_2147667651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Loktrom.B"
        threat_id = "2147667651"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Loktrom"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 43 3a 5c 57 49 4e 44 ce 57 53 5c e5 f5 f0 6c ee 72 e5 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 4c 6f 6b 6f 4d 6f 54 4f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Loktrom_B_2147667651_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Loktrom.B"
        threat_id = "2147667651"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Loktrom"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 03 03 00 00 be ?? ?? 40 00 8d bd c8 f3 ff ff f3 a5 a4 c7 45 f8 ?? 00 00 00 c7 45 f0 00 00 00 00 e8 14 01 00 00 89 45 f4 c7 45 f0 00 00 00 00 eb 09 8b 4d f0 83 c1 01 89 4d f0 8b 55 f0 3b 55 f4 0f 8d d0 00 00 00 8b 45 f0 8a 8c 05 c8 f3 ff ff 88 4d fe 8b 55 f0 83 c2 01 89 55 dc 0f be 45 fe 8b 4d dc 33 4d f8 03 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Loktrom_B_2147667651_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Loktrom.B"
        threat_id = "2147667651"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Loktrom"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 6f 6b 6f 4d 6f 54 4f 00}  //weight: 1, accuracy: High
        $x_1_2 = "Pliqpay_monexy" ascii //weight: 1
        $x_1_3 = "taskkill /F /IM explorer.exe" ascii //weight: 1
        $x_1_4 = "System\\CurrentControlSet\\Control\\SafeBoot\\minimal" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "alfaababagalamaga" ascii //weight: 1
        $x_1_8 = "KLBTBTNBITBTN1_BITMAP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Loktrom_B_2147667651_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Loktrom.B"
        threat_id = "2147667651"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Loktrom"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 40 00 80 60 27 ef 84 d2 74 04 80 48 27 10 8b 48 1c e3 14 50 74 12 ff 15 ?? ?? ?? ?? 58 6a 05 ff 70 1c e8}  //weight: 1, accuracy: Low
        $x_1_2 = {66 c7 80 38 01 00 00 01 01 80 48 34 30 8b 90 ba 00 00 00 83 c2 16 89 90 c2 00 00 00 5a 50 e8}  //weight: 1, accuracy: High
        $x_1_3 = {f0 e0 e2 e8 eb e0 ec 20 fd ea f1 ef eb f3 e0 f2 e0 f6 e8 e8 20 ce d1 20 57 69 6e 64 6f 77 73 2e}  //weight: 1, accuracy: High
        $x_1_4 = {cf f0 e8 eb ee e6 e5 ed e8 e5 ec 20 4d 69 63 72 6f 73 6f 66 74 20 53 65 63 75 72 69 74 79 20 45 73 73 65 6e 74 69 61 6c 73}  //weight: 1, accuracy: High
        $x_1_5 = "%CF%F0%E8%EB%EE%E6%E5%ED%E8%E5%EC+Microsoft+Security+Essentials" ascii //weight: 1
        $x_1_6 = "%EA%EE%F0%EF%EE%F0%E0%F6%E8%E8+Microsoft%2E" ascii //weight: 1
        $x_1_7 = {ea ee f0 ef ee f0 e0 f6 e8 e8 20 4d 69 63 72 6f 73 6f 66 74 2e}  //weight: 1, accuracy: High
        $x_1_8 = {57 49 4e 44 4f 57 53 20 c7 c0 c1 cb ce ca c8 d0 ce c2 c0 cd}  //weight: 1, accuracy: High
        $x_1_9 = {ed e0 20 f1 f3 ec ec f3 20 35 30 30 20 f0 f3 e1 eb e5 e9 2e}  //weight: 1, accuracy: High
        $x_1_10 = {2f 66 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_11 = {f2 e5 f0 ec e8 ed e0 eb e0 20 e1 f3 e4 e5 f2 20 ed e0 ef e5 f7 e0 f2 e0 ed 20 ea ee e4 20}  //weight: 1, accuracy: High
        $x_1_12 = {c2 e0 f8 20 ea ee ec ef fc fe f2 e5 f0 20 e7 e0 e1 eb ee ea e8 f0 ee e2 e0 ed 20 e7 e0 20 ef f0 ee f1 ec ee f2 f0 2c 20 ea ee ef e8 f0 ee e2 e0 ed e8 e5}  //weight: 1, accuracy: High
        $x_2_13 = {75 68 6a 11 e8 ?? ?? ?? ?? 93 6a 12 e8 ?? ?? ?? ?? 09 d8 78 48}  //weight: 2, accuracy: Low
        $x_1_14 = {00 65 78 70 6b 69 6c 6c 3d}  //weight: 1, accuracy: High
        $x_1_15 = {c3 77 69 6e 64 6f 77 73 73 65 63 75 72 69 74 79 00}  //weight: 1, accuracy: High
        $x_1_16 = "C:\\setup.rnd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Loktrom_2147667867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Loktrom"
        threat_id = "2147667867"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Loktrom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {64 8b 15 30 00 00 00 89 55 f8 8b 55 f8 8b 52 0c 8b}  //weight: 5, accuracy: High
        $x_5_2 = {64 8b 05 30 00 00 00 89 45 fc 8b 45 fc 8b 40 0c 89}  //weight: 5, accuracy: High
        $x_2_3 = {8a 18 33 59 04 88 18 40 4a 75}  //weight: 2, accuracy: High
        $x_2_4 = {8a 08 8b 5d ?? 33 4b 04 88 08 40 4a 75}  //weight: 2, accuracy: Low
        $x_2_5 = {8a 02 33 46 04 88 02 42 49 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Loktrom_K_2147679064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Loktrom.K"
        threat_id = "2147679064"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Loktrom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 03 8b 13 8b 52 2c 89 42 25 c7 42 21}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 8b 46 18 8b 40 1c 50 e8 ?? ?? ?? ?? 8b d8 85 db 74 ?? 8b 46 18 3b 58 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Loktrom_L_2147679167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Loktrom.L"
        threat_id = "2147679167"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Loktrom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "135"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {83 c0 09 89 44 24 10 8b 44 24 04 05 f1 00 00 00 89 44 24 14 8b 44 24 08 83 e8 16 89 44 24 18 8b 44 24 0c 83 e8 6e 89 44 24 1c}  //weight: 100, accuracy: High
        $x_15_2 = {31 29 20 cd e0 e9 e4 e8 f2 e5 20 e1 eb e8 e6 e0 e9 f8 e8 e9 20 f2 e5 f0 ec e8 ed e0 eb 20 ee ef}  //weight: 15, accuracy: High
        $x_15_3 = {ee e9 20 f1 e2 ff e7 e8 2c 20 ed e0 ef f0 e8 ec e5 f0 20 49 42 4f 58 2c 20 32 34 4e 6f 6e 53 74 6f 70 2c}  //weight: 15, accuracy: High
        $x_15_4 = {f2 20 f2 e5 f0 ec e8 ed e0 eb e0 29 20 2d 2d 3e 20 22 57 65 62 4d 6f 6e 65 79 22}  //weight: 15, accuracy: High
        $x_15_5 = {cb ce ca c8 d0 ce c2 ca c8 20 57 49 4e 44 4f 57 53 20 cd c5 ce c1 d5 ce c4 c8 cc ce 20 ce cf cb}  //weight: 15, accuracy: High
        $x_10_6 = "alfaababagalamaga" ascii //weight: 10
        $x_10_7 = "KLBTBTNBITBTN1_BITMAP" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_15_*) and 2 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_15_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 3 of ($x_15_*))) or
            (all of ($x*))
        )
}

