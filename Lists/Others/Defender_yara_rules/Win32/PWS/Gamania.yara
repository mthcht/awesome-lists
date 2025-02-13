rule PWS_Win32_Gamania_A_2147583267_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Gamania.gen!A"
        threat_id = "2147583267"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamania"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CreateToolhelp32Snapshot" ascii //weight: 2
        $x_2_2 = "&subject=" ascii //weight: 2
        $x_2_3 = "&sender=" ascii //weight: 2
        $x_2_4 = "cgi-bin/login.cgi?srv=" ascii //weight: 2
        $x_2_5 = "Accept-Language: zh-cn" ascii //weight: 2
        $x_2_6 = "SetWindowsHookExA" ascii //weight: 2
        $x_2_7 = "GamaGoodLock.aspx" ascii //weight: 2
        $x_2_8 = ".gamania.com/" ascii //weight: 2
        $x_2_9 = "Internet Explorer_Server" ascii //weight: 2
        $x_1_10 = "IHTMLElementCollection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Gamania_B_2147583511_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Gamania.gen!B"
        threat_id = "2147583511"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamania"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {26 73 75 62 6a 65 63 74 3d 00 00 00 ff ff ff ff 08 00 00 00 26 73 65 6e 64 65 72 3d}  //weight: 5, accuracy: High
        $x_5_2 = {47 45 54 20 00 00 00 00 ff ff ff ff 0b 00 00 00 20 48 54 54 50 2f 31 2e 30 0d 0a 00 ff}  //weight: 5, accuracy: High
        $x_5_3 = {0d 0a 00 00 ff ff ff ff 18 00 00 00 41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e 0d 0a 00 00 00 00 ff ff ff ff 40}  //weight: 5, accuracy: High
        $x_10_4 = {85 f6 7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 ?? 8d 45 f4 8b d3}  //weight: 10, accuracy: Low
        $x_3_5 = "C:\\game" ascii //weight: 3
        $x_3_6 = "game.txt" ascii //weight: 3
        $x_1_7 = "SetWindowsHookExA" ascii //weight: 1
        $x_5_8 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 70 6c 69 6e 65 61 67 65 2e 63 6f 6d 2f 66 69 72 6f 2f 6d 61 69 6c 2e 61 73 70 3f 74 6f 6d 61 69 6c 3d 31 36 33 40 31 36 33 2e 63 6f 6d 26 6d 61 69 6c 62 6f 64 79 3d 00 00}  //weight: 5, accuracy: High
        $x_2_9 = {67 61 6d 65 3a 6a 70 72 6f 0d 0a 73 65 72 76 65 72 3a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*))) or
            ((4 of ($x_5_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Gamania_C_2147601655_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Gamania.gen!C"
        threat_id = "2147601655"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamania"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 e8 ?? ?? ?? ?? 8b 55 f4 8b c7 e8 ?? ?? ?? ?? ff 45 f8 4e 75 d9}  //weight: 8, accuracy: Low
        $x_5_2 = {8b 4d fc 8a 0c 01 80 f1 86 51 59 88 0c 03 40 4a 75 ee}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Gamania_D_2147601806_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Gamania.gen!D"
        threat_id = "2147601806"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamania"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "102"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 e8 ?? ?? ?? ?? 8b 55 f4 8b c7 e8 ?? ?? ?? ?? ff 45 f8 4e 75 d9}  //weight: 100, accuracy: Low
        $x_3_2 = {89 44 24 18 8b 44 24 10 8b d0 83 ea 0c 83 c0 0a 2b c2 0f 8c 71 01 00 00 40 89 44 24 2c 89 54 24 20 83 7c 24 20 00 0f 8c 4f 01 00 00 8b 44 24 20 3b 44 24 18 0f 8f 41 01 00 00 8b 44 24 0c 8b d0 83 ea 17 83 c0 15 2b c2 0f 8c 2d 01 00 00}  //weight: 3, accuracy: High
        $x_3_3 = {74 03 4f 75 d2 85 db 74 0f 6a 00 6a 00 68 f5 00 00 00 53 e8 ?? ?? ff ff 43 00 74 11 6a 00 6a 00 68 f5 00 00 00 53 e8}  //weight: 3, accuracy: Low
        $x_3_4 = {75 2e 6a f4 53 e8 ?? ?? ff ff 3d b4 00 00 00 74 23 6a f0 53 e8 ?? ?? ff ff a8 20 75 17 6a 00 6a 00 68 d2 00 00 00 53 e8 ?? ?? ff ff}  //weight: 3, accuracy: Low
        $x_3_5 = {8a 18 8b cb 80 e1 07 81 e1 ff 00 00 00 51 b9 07 00 00 00 5f 2b cf bf 01 00 00 00 d3 e7 33 c9 8a cb c1 e9 03 0f b6 0c 0e 23 f9 74 1a 8b ca 83 e1 07 51 b9 07 00 00 00 5b 2b cb b3 01 d2 e3 8b ca c1 e9 03 08 1c 0c 42 40 83 fa 40 75 b3}  //weight: 3, accuracy: High
        $x_3_6 = {7e 2c be 01 00 00 00 8d 45 f0 8b 55 fc 0f b6 54 32 ff 4a d1 fa 79 03 83 d2 00 e8 ?? ?? ff ff 8b 55 f0 8d 45 f8 e8 ?? ?? ff ff 46 4b 75 d9}  //weight: 3, accuracy: Low
        $x_3_7 = {7e 23 be 01 00 00 00 b8 18 00 00 00 e8 ?? ?? ff ff 83 c0 61 50 8b c7 e8 ?? ?? ff ff 5a 88 54 30 ff 46 4b 75 e2}  //weight: 3, accuracy: Low
        $n_200_8 = {0f 84 2d 01 00 00 6a 00 53 e8 ?? ?? ff ff 8b f0 81 fe 00 00 00 01 0f 83 11 01 00 00 3b 35 ?? ?? ?? ?? 7c 34}  //weight: -200, accuracy: Low
        $n_200_9 = {8b 55 fc e8 ?? ?? ff ff 8b 85 ?? ?? ff ff e8 ?? ?? ff ff 56 57 e8 ?? ?? ff ff 85 c0 75 84 57 e8 ?? ?? ff ff c7 06 16 00 00 00}  //weight: -200, accuracy: Low
        $x_3_10 = {d2 e1 f6 cd ef ee ae e5 f8 e5 00}  //weight: 3, accuracy: High
        $x_3_11 = {d2 e1 f6 cd ef ee c3 ec e1 f3 f3 00}  //weight: 3, accuracy: High
        $x_3_12 = {d3 ef e6 f4 f7 e1 f2 e5 dc c8 e1 e3 eb e5 f2 dc 00}  //weight: 3, accuracy: High
        $x_1_13 = {c9 d0 c1 d2 cd cf d2 ae c5 d8 c5 00}  //weight: 1, accuracy: High
        $x_2_14 = "JumpHookOn" ascii //weight: 2
        $x_1_15 = "JumpHookOff" ascii //weight: 1
        $x_1_16 = {64 65 6c 20 25 30 00}  //weight: 1, accuracy: High
        $x_1_17 = {6a 53 74 61 00}  //weight: 1, accuracy: High
        $x_1_18 = {6a 53 74 62 00}  //weight: 1, accuracy: High
        $x_1_19 = {ae c5 d8 c5 00}  //weight: 1, accuracy: High
        $x_1_20 = {ae d4 d8 d4 00}  //weight: 1, accuracy: High
        $x_1_21 = {cd e1 f0 c6 e9 ec e5 00}  //weight: 1, accuracy: High
        $x_1_22 = {c3 cc d3 c9 c4 dc 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Gamania_E_2147603136_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Gamania.gen!E"
        threat_id = "2147603136"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamania"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 e8 ?? ?? ?? ?? 8b 55 f4 8b c7 e8 ?? ?? ?? ?? ff 45 f8 4e 75 d9}  //weight: 10, accuracy: Low
        $x_1_2 = {6a 00 8d 45 fc 50 68 01 04 00 00 8d 85 ef fb ff ff 50 56 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Gamania_B_2147606000_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Gamania.B"
        threat_id = "2147606000"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamania"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c1 f9 02 78 11 fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3}  //weight: 5, accuracy: High
        $x_5_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 65 74 67 61 6d 65 72 6a 70 2e 63 6f 6d 2f 6a 70 2f 6d 61 69 6c 2e 61 73 70 3f 74 6f 6d 61 69 6c 3d 31 36 33 40 31 36 33 2e 63 6f 6d 26 6d 61 69 6c 62 6f 64 79 3d 00}  //weight: 5, accuracy: High
        $x_1_3 = {47 45 54 20 00 00 00 00 ff ff ff ff 0b 00 00 00 20 48 54 54 50 2f 31 2e 30 0d 0a 00 ff}  //weight: 1, accuracy: High
        $x_1_4 = {0d 0a 00 00 ff ff ff ff 18 00 00 00 41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e 0d 0a 00 00 00 00 ff ff ff ff 40}  //weight: 1, accuracy: High
        $x_1_5 = "SetWindowsHookExA" ascii //weight: 1
        $x_2_6 = {67 61 6d 65 3a 6a 70 72 6f 0d 0a 73 65 72 76 65 72 3a}  //weight: 2, accuracy: High
        $x_1_7 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

