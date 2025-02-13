rule TrojanSpy_Win32_Bafi_A_2147652421_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bafi.A"
        threat_id = "2147652421"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 00 43 00 4c 00 49 00 43 00 4b 00 44 00 42 00 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {46 49 44 55 43 49 41 2e 44 45 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {fa 02 6f dc 3f 10 c7 b9 1e a0 c6 85 94 4d 5e 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Bafi_P_2147652637_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bafi.P"
        threat_id = "2147652637"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {e3 0f 53 6a 01 68 f1 00 00 00 51 ff 15 ?? ?? ?? ?? 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 8d 45 ?? 50 ff 75 ?? ff 15 ?? ?? ?? ?? ff 75 ?? ff 75 ?? ff 15}  //weight: 10, accuracy: Low
        $x_1_2 = {00 62 61 6e 6b 5c 73 72 76 62 6c 63 6b 35 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 25 73 6e 65 74 62 61 6e 6b 5f 25 73 5f 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 6e 61 74 69 6f 6e 61 6c 69 72 69 73 68 62 61 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 62 61 6e 6b 6f 66 61 6d 65 72 69 63 61 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 6e 61 74 69 6f 6e 61 6c 63 69 74 79 63 61 72 64 73 65 72 76 69 63 65 73 6f 6e 6c 69 6e 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Bafi_P_2147652637_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bafi.P"
        threat_id = "2147652637"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {32 c2 32 e2 88 66 ?? 88 47 ?? 8a 46 ?? 8a 67 ?? 32 c2 32 e2 88 66}  //weight: 3, accuracy: Low
        $x_2_2 = "\\appconf32.exe" ascii //weight: 2
        $x_2_3 = ".wma.xml.bat." ascii //weight: 2
        $x_2_4 = "&version2=" ascii //weight: 2
        $x_1_5 = "\\TSTheme.exe" ascii //weight: 1
        $x_1_6 = "/index.php" ascii //weight: 1
        $x_1_7 = "nationalirishbank" ascii //weight: 1
        $x_1_8 = "wellsfargo" ascii //weight: 1
        $x_1_9 = "discovercard" ascii //weight: 1
        $x_1_10 = "paypal" ascii //weight: 1
        $x_1_11 = "chase" ascii //weight: 1
        $x_1_12 = "\\TypedURLs" ascii //weight: 1
        $x_1_13 = "skype.exe" ascii //weight: 1
        $x_1_14 = "avgtray.exe" ascii //weight: 1
        $x_1_15 = "bdagent.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Bafi_C_2147652895_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bafi.C"
        threat_id = "2147652895"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "fiducia.de" wide //weight: 6
        $x_1_2 = "_ifrm.htm" wide //weight: 1
        $x_1_3 = "tpac_%d.mvt" wide //weight: 1
        $x_1_4 = "VkeyGrabberW" ascii //weight: 1
        $x_1_5 = {47 65 74 4b 65 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Bafi_D_2147653575_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bafi.D"
        threat_id = "2147653575"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 00 41 00 4e 00 4b 00 00 00 00 00 44 00 45 00 55 00 00 00 57 00 00 00 55 72 6c 00 2e 00 68 00 74 00 6d}  //weight: 1, accuracy: High
        $x_1_2 = "tpac_%d.mvt" wide //weight: 1
        $x_1_3 = "_ifrm.htm" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Bafi_Q_2147656264_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bafi.Q"
        threat_id = "2147656264"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 db 33 c0 99 8a 11 80 ca 20 03 c2 8d 49 02 66 39 19 75 ?? 3d e0 1e 00 00 75 ?? c7 44 3c ?? 01 00 00 80 c7 05 ?? ?? ?? ?? 01 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Bafi_Q_2147656264_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bafi.Q"
        threat_id = "2147656264"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 11 80 ca 20 03 c2 90 8d 49 02 66 39 19 75 f0 3d e0 1e 00 00 75 5e c7 44 3c 1c 01 00 00 80}  //weight: 1, accuracy: High
        $x_1_2 = {00 61 64 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 43 6c 6f 73 65 47 75 61 72 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 53 65 74 47 75 61 72 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {84 c0 74 11 66 83 f8 61 7c 04 66 83 e8 20 03 d0 c1 c2 03 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Bafi_Q_2147656264_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bafi.Q"
        threat_id = "2147656264"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 5a 35 4e d7 75 05 e8 ?? 00 00 00 b8 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {81 39 8b ff 55 8b 75 08 8d 05 ?? ?? 00 10 eb 0e 80 39 e9 74 2d}  //weight: 1, accuracy: Low
        $x_1_3 = {81 39 8b ff 55 8b [0-2] 75 08 8d 05 ?? ?? 00 10 74 13 80 39 e9 74 32}  //weight: 1, accuracy: Low
        $x_1_4 = {43 6c 6f 73 65 47 75 61 72 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 65 74 47 75 61 72 64 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Bafi_E_2147658156_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bafi.E"
        threat_id = "2147658156"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 00 43 00 4c 00 49 00 43 00 4b 00 44 00 42 00 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "tpac_%d.mvt" wide //weight: 1
        $x_1_3 = "VkeyGrabberW" ascii //weight: 1
        $x_1_4 = "Module_Raw" wide //weight: 1
        $x_1_5 = "showpopup" wide //weight: 1
        $x_1_6 = "Adobe PDF Reader Link Helper" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Bafi_E_2147658156_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bafi.E"
        threat_id = "2147658156"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Module_Raw" wide //weight: 1
        $x_1_2 = "showpopup" wide //weight: 1
        $x_1_3 = {4d 00 43 00 4c 00 49 00 43 00 4b 00 44 00 42 00 4c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "Software\\Classes\\linkrdr.AIEbho" wide //weight: 1
        $x_10_5 = {40 25 0f 00 00 80 79 ?? 48 83 c8 f0 40 8b 16 88 45 ff 8a 44 39 02 32 c3 88 04 11 8a 5c 39 02 41 3b ?? ?? 7c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Bafi_E_2147658156_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bafi.E"
        threat_id = "2147658156"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 fc 06 68 ?? ?? ?? ?? 8d 8d c0 fe ff ff e8 ?? ?? ?? ?? c6 45 fc 0a 68 ?? ?? ?? ?? 8d 95 c0 fe ff ff 52 8d 85 9c fe ff ff 50 e8 ?? ?? ?? ?? 83 c4 0c 89 85 38 fe ff ff 8b 8d 38 fe ff ff 89 8d 34 fe ff ff c6 45 fc 0b 68 ?? ?? ?? ?? 8b 95 34 fe ff ff 52}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 4d ff 03 c8 88 4d ff 0f b6 55 fe 83 c2 01 81 e2 0f 00 00 80 79 05 4a 83 ca f0 42 88 55 fe 8b 45 08 03 45 f0 0f b6 08 0f b6 55 ff 33 ca 8b 45 e8 8b 10 8b 45 f0 88 0c 02 8b 4d 08 03 4d f0 8a 11 88 55 ff eb 9d}  //weight: 1, accuracy: High
        $x_1_3 = "\\CurrentVersion\\Explorer\\Browser Helper Objects\\" wide //weight: 1
        $x_1_4 = "https://www.facebook.com/login.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Bafi_F_2147658183_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bafi.F"
        threat_id = "2147658183"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 45 ff 02 98 ?? ?? ?? ?? 40 25 0f 00 00 80 79 05 48 83 c8 f0 40 8b ?? 88 45 ff 03 04 03 08 8a 44 39 02 8a 04 39 8b 45 08 8d 34 01 8a 06 32 c3 88 04 11 8a 03 03 02 01 5c 39 02 1c 39 1e 41 3b 4d f8 7c}  //weight: 10, accuracy: Low
        $x_10_2 = {81 e1 0f 00 00 80 79 05 49 83 c9 f0 41 (8a ?? ?? (32 ?? 88 ?? ?? ??|88 ?? ?? ?? 32 ??)|88 ?? ?? (32 ?? 88 ?? ?? ??|8a ?? ?? ?? 32 ??)) 8b (??|?? ??) 88 ?? ?? 8a 03 03 03 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3b ?? 0f b6 (?? ??|?? ?? ??) 02}  //weight: 10, accuracy: Low
        $x_1_3 = {f1 f4 6d 2e 11 1f b2 b0 a2 75 e5 fc 51 09 2a 92 6c 6f f7 b8 98 a6 3a 38 74 47 0b 22 f0 a8 cd 35 9e a1 d3 94 a8 b6 3c 3a 28 fb 7d 94 6f 27 56 be}  //weight: 1, accuracy: High
        $x_1_4 = {e0 e3 9c 5d e0 ee e1 df 71 44 16 2d a6 5e 75 dd 52 55 11 d2 7e 8c 44 42 4a 1d 5d 74 82 3a 5f c7 1f 22 52 13 29 37 bf bd ab 7e fe 15 e8 a0 e9 51}  //weight: 1, accuracy: High
        $x_1_5 = {f1 f4 6d 2e 11 1f b2 b0 a2 75 e5 fc 51 09 2a 92 1c 1f 47 08 48 56 8a 88 84 57 0d 24 ff b7 c0 28 bd c0 b4 75 de ec f1 ef 70 43 0a 21 fb b3 ce 36}  //weight: 1, accuracy: High
        $x_1_6 = {46 6b 1a 2d bc 38 9d 73 89 9e cd e9 63 1a 39 3d 68 8d f1 04 fd 79 4b 21 c9 de 95 b1 48 ff 95 99 c4 e9 de f1 e2 5e 6e 44 be d3 9a b6 49 00 92 96}  //weight: 1, accuracy: High
        $x_1_7 = {36 5b 0a 1d cc 48 8d 63 99 ae bd d9 73 2a 09 0d 38 5d 0a 1d dd 59 7e 54 b8 cd 8c a8 76 2d 42 46 7e a3 ce e1 1d 99 24 fa f3 08 43 5f aa 61 3f 43}  //weight: 1, accuracy: High
        $x_1_8 = {8d 90 c9 8a b5 c3 1e 1c 4e 21 31 48 8d 45 6e d6 a8 ab d2 93 af bd 10 0e 52 25 27 3e c3 7b 1c 84 1b 1e 4b 0c 22 30 b9 b7 aa 7d f5 0c 1e d6 b0 18}  //weight: 1, accuracy: High
        $x_1_9 = {9d a0 d9 9a a5 b3 2e 2c 3e 11 41 58 fd b5 9e 06 88 8b f2 b3 8f 9d 30 2e 32 05 47 5e a3 5b 3c a4 6b 6e 1b dc 72 80 49 47 1a ed 65 7c 8e 46 20 88}  //weight: 1, accuracy: High
        $x_1_10 = {9c 9f d8 99 a4 b2 2d 2b 3d 10 42 59 f2 aa 89 f1 be c1 bc 7d d1 df f2 f0 70 43 05 1c e5 9d f2 5a d4 d7 8c 4d e5 f3 f4 f2 67 3a 30 47 d3 8b e5 4d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Bafi_H_2147659675_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bafi.H"
        threat_id = "2147659675"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 45 ff 02 98 ?? ?? ?? ?? (0f b6|8a) 45 ff fe c0 0f b6 c0 25 0f 00 00 80 79 05}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 44 24 18 0f b6 d0 02 9a ?? ?? ?? ?? 04 01 0f b6 c0 25 0f 00 00 80 79 05}  //weight: 1, accuracy: Low
        $x_10_3 = {01 09 0b 34 0b 83 25 1b 0c 12 c7 f8 d4 8e eb 8d}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Bafi_I_2147659695_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bafi.I"
        threat_id = "2147659695"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 c0 25 0f 00 00 80 79 05 48 83 c8 f0 40 (88 44 24 18 8a|88 45 ff 8b 45 08 8d 14 01) 32 c3}  //weight: 10, accuracy: Low
        $x_5_2 = {8d 13 0b 37 79 1f ed cf 78 ae 63 30 70 8f ec 94}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Bafi_J_2147659893_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bafi.J"
        threat_id = "2147659893"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f b6 45 ff 02 98 ?? ?? ?? ?? 40 25 0f 00 00 80 79 05 48 83 c8 f0 40 88 45 ff 8a 01 8a d0 32 d3 88 14 0e}  //weight: 3, accuracy: Low
        $x_3_2 = {0f b6 45 fe 0f b6 80 ?? ?? ?? ?? 0f b6 4d ff 03 c8 88 4d ff 0f b6 45 fe 40 25 0f 00 00 80 79 05 48 83 c8 f0 40 88 45 fe 8b 45 ?? 03 45 ?? 0f b6 00 0f b6 4d ff 33 c1}  //weight: 3, accuracy: Low
        $x_2_3 = "Time: %s Url: %s Referrer: %s IEver: %s -->" wide //weight: 2
        $x_2_4 = "sses\\linkrdr.AIEbho" wide //weight: 2
        $x_2_5 = {4d 00 43 00 4c 00 49 00 43 00 4b 00 44 00 42 00 4c 00 00 00 52 00 43 00 4c 00 49 00 43 00 4b 00 00 00}  //weight: 2, accuracy: High
        $x_2_6 = {3c 00 43 00 4c 00 45 00 41 00 52 00 3e 00 00 00 73 00 68 00 6f 00 77 00 70 00 6f 00 70 00 75 00 70 00 00 00}  //weight: 2, accuracy: High
        $x_2_7 = {73 00 68 00 6f 00 77 00 70 00 6f 00 70 00 75 00 70 00 00 00 3c 00 43 00 4c 00 45 00 41 00 52 00 3e 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Bafi_M_2147660371_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bafi.M"
        threat_id = "2147660371"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Module_Raw" wide //weight: 1
        $x_1_2 = "showpopup" wide //weight: 1
        $x_1_3 = "Adobe_PDF_Reader_Hlp_Mtx" wide //weight: 1
        $x_1_4 = {81 e1 0f 00 00 80 79 05 49 83 c9 f0 41 (8a ?? ?? (32 ?? 88 ?? ?? ??|88 ?? ?? ?? 32 ??)|88 ?? ?? (32 ?? 88 ?? ?? ??|8a ?? ?? ?? 32 ??)) 8b (??|?? ??) 88 ?? ?? 8a 03 03 03 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3b ?? 0f b6 (?? ??|?? ?? ??) 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Bafi_N_2147661266_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bafi.N"
        threat_id = "2147661266"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "210"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {81 e1 0f 00 00 80 79 05 49 83 c9 f0 41 88 4d ff 8a 4c 30 02 32 cb 8b 1a 88 0c 18 8a 5c 30 02 40 3b c7 7c d1}  //weight: 100, accuracy: High
        $x_100_2 = {53 00 54 00 50 00 41 00 43 00 00 00 57 00 45 00}  //weight: 100, accuracy: High
        $x_20_3 = "Classes\\linkrd.AIEbho\\CLSID" wide //weight: 20
        $x_10_4 = "8BBE6A70-EF84-47FA-B5DE-EDD0DF18461F" wide //weight: 10
        $x_10_5 = "F535DD2D-9339-48ED-A378-61084B1049AB" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_10_*))) or
            ((2 of ($x_100_*) and 1 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Bafi_O_2147667327_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bafi.O"
        threat_id = "2147667327"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 e1 0f 00 00 80 79 05 49 83 c9 f0 41 8b [0-2] 88 4d ?? 8a 4c 38 02 32 cb}  //weight: 10, accuracy: Low
        $x_10_2 = {25 0f 00 00 80 79 05 48 83 c8 f0 40 88 45 fe 8b 45 08 03 45 f8 0f b6 00 0f b6 4d ff 33 c1}  //weight: 10, accuracy: High
        $x_2_3 = {25 cd 77 13 9b d6 11 19 04 01 03 7b 65 b9 fb c2}  //weight: 2, accuracy: High
        $x_2_4 = {2f 19 8b db 37 0e 07 05 22 5b 49 01 6f 7d 19 13}  //weight: 2, accuracy: High
        $x_2_5 = {9d e1 13 15 05 04 03 01 22 5b 49 01 79 7d f5 5a}  //weight: 2, accuracy: High
        $x_2_6 = {0b d3 8b 17 51 1b c1 b5 93 a1 87 f1 e8 d7 92 c6}  //weight: 2, accuracy: High
        $x_2_7 = {33 0b 13 e9 b5 e3 5d 83 93 a1 87 f1 e8 d8 92 c7}  //weight: 2, accuracy: High
        $x_2_8 = {34 0b 13 e9 b5 e4 5d 83 93 a1 87 f1 e9 d8 10 01}  //weight: 2, accuracy: High
        $x_2_9 = {14 50 6a 04 6a 00 ff 75 10 ff 75 fc e8 54 fd 00}  //weight: 2, accuracy: High
        $x_2_10 = {35 13 81 df 51 ee 09 65 11 0b eb f0 ee d9 0c 01}  //weight: 2, accuracy: High
        $x_2_11 = {36 12 13 17 01 ef 07 0b 6b 6e ec f9 26 07 0b 02}  //weight: 2, accuracy: High
        $x_2_12 = {38 13 11 17 01 ef 07 6e 6b 0c ec f7 26 07 0d 03}  //weight: 2, accuracy: High
        $x_2_13 = {93 8b be e9 b6 17 5b 83 b1 0b 87 f3 87 10 11 06}  //weight: 2, accuracy: High
        $x_2_14 = {0b b4 d0 6f a5 ae 05 09 74 4f f0 8c cd ac 2f ea}  //weight: 2, accuracy: High
        $x_2_15 = {8e 83 bf e8 51 17 5b 83 b1 d3 87 f3 21 11 11 07}  //weight: 2, accuracy: High
        $x_2_16 = "C:\\WINDOWS\\SYSTEM32\\xmldm\\" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Bafi_R_2147679561_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bafi.R"
        threat_id = "2147679561"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "\\Mozilla\\Firefox\\extensions" wide //weight: 5
        $x_5_2 = {4a 61 76 61 [0-1] 53 74 72 69 6e 67 48 65 6c 70 65 72}  //weight: 5, accuracy: Low
        $x_3_3 = "{33044118-6597-4D2F-ABEA-7974BB185379}" wide //weight: 3
        $x_3_4 = "{184AA5E6-741D-464a-820E-94B3ABC2F3B4}" wide //weight: 3
        $x_3_5 = "{E634117B-33A8-4C70-8210-198010F03834}" wide //weight: 3
        $x_1_6 = ".clb" wide //weight: 1
        $x_1_7 = "UAs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

