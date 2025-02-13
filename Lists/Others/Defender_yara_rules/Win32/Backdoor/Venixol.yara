rule Backdoor_Win32_Venixol_A_2147678469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venixol.A"
        threat_id = "2147678469"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venixol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "230"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "schtasks.exe /delete /f /tn XMLRPCSRV3" wide //weight: 100
        $x_50_2 = {a7 4f 73 08 24 2a 15 1f 04 f8 25 34 b5 57 d0 b0 50 91 fa 4d}  //weight: 50, accuracy: High
        $x_50_3 = {b6 5a 7a 06 7e 3d 5e 0d 08 ee 3e 39 ae 4b c6 a5 1d 97 e6 0e c5 64}  //weight: 50, accuracy: High
        $x_50_4 = {bf 5e 64 1d 35 3d 48 50 1d e0 20 31 aa 59 d4 b7 50 91 fa 4d}  //weight: 50, accuracy: High
        $x_30_5 = {bf 4f 76 47 3f 21 5e 50 00 e6 2f 28 a9 4b d9 a2 0a dc f6 4f cd}  //weight: 30, accuracy: High
        $x_30_6 = {91 6d 5b 47 06 0a 69 37 3e c6 0b 14 e8 76 f3 90}  //weight: 30, accuracy: High
        $x_30_7 = "X3N1cGVyX2NzbTp6dGUkNzQxNTcwOGF2bGlz" ascii //weight: 30
        $x_30_8 = "VENIX3N1cGVyX2NzbTp6dGUkNzQxNTcwOGF2bGlz" ascii //weight: 30
        $x_30_9 = "YWRtaW46cGFzc3dvcmQ=" ascii //weight: 30
        $x_30_10 = "MTIzNDoxMjM0" ascii //weight: 30
        $x_20_11 = {b8 68 58 4d 56 bb 65 d4 85 86 b9 0a 00 00 00 66 ba 58 56 ed 89 5d ec 5b 83 4d fc ff 33 c0 81 7d ec 68 58 4d 56}  //weight: 20, accuracy: High
        $x_20_12 = {6a 53 66 89 4d fc 33 c9 66 89 4d fe 59 6a 62 66 89 4d d0 59 6a 69 66 89 4d d2 59 6a 65}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 5 of ($x_30_*) and 2 of ($x_20_*))) or
            ((1 of ($x_50_*) and 6 of ($x_30_*))) or
            ((2 of ($x_50_*) and 3 of ($x_30_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*) and 4 of ($x_30_*) and 1 of ($x_20_*))) or
            ((2 of ($x_50_*) and 5 of ($x_30_*))) or
            ((3 of ($x_50_*) and 2 of ($x_30_*) and 1 of ($x_20_*))) or
            ((3 of ($x_50_*) and 3 of ($x_30_*))) or
            ((1 of ($x_100_*) and 3 of ($x_30_*) and 2 of ($x_20_*))) or
            ((1 of ($x_100_*) and 4 of ($x_30_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 5 of ($x_30_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_30_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 3 of ($x_30_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 2 of ($x_20_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_30_*))) or
            ((1 of ($x_100_*) and 3 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Venixol_B_2147679017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venixol.B"
        threat_id = "2147679017"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venixol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "230"
        strings_accuracy = "High"
    strings:
        $x_130_1 = {8a 04 18 8a 16 02 c2 00 45 fe 0f b6 45 fe 03 c1 8a 18 fe 45 ff 88 1e 88 10 66 0f b6 45 ff}  //weight: 130, accuracy: High
        $x_60_2 = {bf 46 39 08 26 3c 5a 18 08 fb 35 74 b4 4d 00}  //weight: 60, accuracy: High
        $x_60_3 = {b3 49 64 08 36 2a 4f 07 43 fd 39 00}  //weight: 60, accuracy: High
        $x_30_4 = {1b 86 e5 41 c7 74 aa df ae d1 8d c0 58 25 fc 7b 26 04 05 7f 7e 14 97 0c 5f b6 07 92 6d 9e 49 60}  //weight: 30, accuracy: High
        $x_30_5 = {92 4b e9 b6 8b 78 8c a5 0a a4 02 a3 87 cb 78 a9 2e 42 6c 08 6e b1 1f 6d 3a c0 14 12 0c 35 6a de}  //weight: 30, accuracy: High
        $x_30_6 = {35 05 13 4e 6e 10 95 46 1b e0 37 a5 6c 83 4b 35 c9 82 8a 74}  //weight: 30, accuracy: High
        $x_30_7 = {97 9a 92 60 5e 21 83 69 f2 4d 04 c8 8c 92 77 34 a5 f4 11 26 88 5f c4 35 38 e9 21 f8 a3 76 99 c7}  //weight: 30, accuracy: High
        $x_30_8 = {81 5a 65 1f 35 3d 01 5e 2c ff 2d 39 ae 5d 99 f6 50 c0 bb 13 80 39 d4 9f f2 e3 b7 e0 03}  //weight: 30, accuracy: High
        $x_30_9 = {d3 0e ad 2f c7 1e 65 95 9c c4 28 4b 5f d2 33 a1 7d 05 e6 88 99 31 60 ec f8 11 30 cb 0a 98 7a 0a}  //weight: 30, accuracy: High
        $x_30_10 = {b5 5a 63 47 20 27 4b}  //weight: 30, accuracy: High
        $x_30_11 = {f2 0b 27 5a 70 09 54 0c 0f e6 28 3e a3 56}  //weight: 30, accuracy: High
        $x_20_12 = "YWRtaW46" ascii //weight: 20
        $x_20_13 = "VENIX3N1cGVyX2NzbTp6dGUkNzQxNTcwOGF2bGlz" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_30_*) and 1 of ($x_20_*))) or
            ((8 of ($x_30_*))) or
            ((1 of ($x_60_*) and 5 of ($x_30_*) and 1 of ($x_20_*))) or
            ((1 of ($x_60_*) and 6 of ($x_30_*))) or
            ((2 of ($x_60_*) and 3 of ($x_30_*) and 1 of ($x_20_*))) or
            ((2 of ($x_60_*) and 4 of ($x_30_*))) or
            ((1 of ($x_130_*) and 2 of ($x_30_*) and 2 of ($x_20_*))) or
            ((1 of ($x_130_*) and 3 of ($x_30_*) and 1 of ($x_20_*))) or
            ((1 of ($x_130_*) and 4 of ($x_30_*))) or
            ((1 of ($x_130_*) and 1 of ($x_60_*) and 2 of ($x_20_*))) or
            ((1 of ($x_130_*) and 1 of ($x_60_*) and 1 of ($x_30_*) and 1 of ($x_20_*))) or
            ((1 of ($x_130_*) and 1 of ($x_60_*) and 2 of ($x_30_*))) or
            ((1 of ($x_130_*) and 2 of ($x_60_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Venixol_D_2147679537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Venixol.D"
        threat_id = "2147679537"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Venixol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "230"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "schtasks.exe /change /tn XMLRPCSRV3 /disable" wide //weight: 100
        $x_50_2 = {bf 5e 64 1d 35 3d 48 50 1d e0 20 31 aa 59 d4 b7 50 91 fa 4d}  //weight: 50, accuracy: High
        $x_50_3 = {a7 4f 73 08 24 2a 15 1f 04 f8 25 34 b5 57 d0 b0 50 91 fa 4d}  //weight: 50, accuracy: High
        $x_30_4 = "/create /tn XMLRPCSRV3 /tr \"%s\" /sc monthly /f" wide //weight: 30
        $x_30_5 = {91 6d 5b 47 06 0a 69 37 3e c6 0b 14 e8 76 f3 90}  //weight: 30, accuracy: High
        $x_30_6 = {bf 4f 76 47 3f 21 5e 50 00 e6 2f 28 a9 4b d9 a2 0a dc f6 4f cd}  //weight: 30, accuracy: High
        $x_30_7 = {1b 86 e5 41 c7 74 aa df ae d1 8d c0 58 25 fc 7b 26 04 05 7f 7e 14 97 0c 5f b6 07 92 6d 9e 49 60}  //weight: 30, accuracy: High
        $x_30_8 = {92 4b e9 b6 8b 78 8c a5 0a a4 02 a3 87 cb 78 a9 2e 42 6c 08 6e b1 1f 6d 3a c0 14 12 0c 35 6a de}  //weight: 30, accuracy: High
        $x_30_9 = {35 05 13 4e 6e 10 95 46 1b e0 37 a5 6c 83 4b 35 c9 82 8a 74}  //weight: 30, accuracy: High
        $x_30_10 = {97 9a 92 60 5e 21 83 69 f2 4d 04 c8 8c 92 77 34 a5 f4 11 26 88 5f c4 35 38 e9 21 f8 a3 76 99 c7}  //weight: 30, accuracy: High
        $x_20_11 = "YWRtaW46" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_30_*) and 1 of ($x_20_*))) or
            ((1 of ($x_50_*) and 6 of ($x_30_*))) or
            ((2 of ($x_50_*) and 4 of ($x_30_*) and 1 of ($x_20_*))) or
            ((2 of ($x_50_*) and 5 of ($x_30_*))) or
            ((1 of ($x_100_*) and 4 of ($x_30_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 5 of ($x_30_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_30_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 3 of ($x_30_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_30_*))) or
            (all of ($x*))
        )
}

