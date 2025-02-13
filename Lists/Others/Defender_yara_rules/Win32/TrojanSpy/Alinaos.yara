rule TrojanSpy_Win32_Alinaos_E_2147681079_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Alinaos.E"
        threat_id = "2147681079"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Alinaos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 6c 69 6e 61 20 76 01 00 2e 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = {28 28 28 25 3f 5b 42 62 c2 b4 60 5d 3f 29 5b 30 2d 39 5d 7b 31 33 2c 31 39 7d 5c 5e 5b 41 2d 5a 61 2d 7a 5c 73 5d 7b 30 2c 32 36 7d 2f 5b 41 2d 5a 61 2d 7a 5c 73 5d 7b 30 2c 32 36 7d 5c 5e 28 31 5b 32 2d 39 5d 29 28 30 5b 31 2d 39 5d 7c 31 5b 30 2d 32 5d 29 5b 30 2d 39 5c 73 5d 7b 33 2c 35 30 7d 5c 3f 29 5b 3b 5c 73 5d 7b 31 2c 33 7d 28 5b 30 2d 39 5d 7b 31 33 2c 31 39 7d 3d 28 31 5b 32 2d 39 5d 29 28 30 5b 31 2d 39 5d 7c 31 5b 30 2d 32 5d 29 5b 30 2d 39 5d 7b 33 2c 35 30 7d 5c 3f 29 29}  //weight: 1, accuracy: High
        $x_3_3 = {c7 01 00 00 00 00 6a 00 6a 00 6a 00 6a 01 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 45 ?? 85 c0 0f 84 ?? ?? ?? ?? 83 f8 ff 0f 84 ?? ?? ?? ?? 6a 00 6a 00 6a 03 6a 00 6a 00 53 56 50 ff 15}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Alinaos_D_2147681080_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Alinaos.D"
        threat_id = "2147681080"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Alinaos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 6c 69 6e 61 20 76 01 00 2e 01 00}  //weight: 2, accuracy: Low
        $x_2_2 = {53 57 6a 00 6a 00 6a 00 6a 01 68 ?? ?? ?? ?? 89 45 ?? 89 4d ?? 8b fa c7 45 ?? 00 00 00 00 ff 15 ?? ?? ?? ?? 8b d8 89 5d ?? 85 db 0f 84 ?? ?? ?? ?? 83 fb ff 0f 84 ?? ?? ?? ?? 56 6a 00 6a 00 6a 03 6a 00 6a 00 6a 50 68 ?? ?? ?? ?? 53 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Alinaos_C_2147681081_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Alinaos.C"
        threat_id = "2147681081"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Alinaos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 6c 69 6e 61 20 76 01 00 2e 01 00}  //weight: 2, accuracy: Low
        $x_2_2 = {56 56 56 6a 01 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b f8 89 7d ?? 3b fe 0f 84 ?? ?? ?? ?? 83 ff ff 0f 84 ?? ?? ?? ?? 56 56 6a 03 56 56 6a 50 68 ?? ?? ?? ?? 57 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Alinaos_B_2147681082_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Alinaos.B"
        threat_id = "2147681082"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Alinaos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 6c 69 6e 61 20 76 01 00 2e 01 00}  //weight: 2, accuracy: Low
        $x_2_2 = {56 56 56 6a 01 68 ?? ?? ?? ?? ff 15 98 91 41 00 8b d8 89 5d ?? 3b de 0f 84 ?? ?? ?? ?? 83 fb ff 0f 84 ?? ?? ?? ?? 56 56 6a 03 56 56 6a 50 68 ?? ?? ?? ?? 53 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Alinaos_A_2147684937_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Alinaos.A"
        threat_id = "2147684937"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Alinaos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 64 6c 65 78 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 5c 2e 5c 70 69 70 65 5c 61 6c 69 6e 61 00}  //weight: 1, accuracy: High
        $x_1_3 = {f7 e1 c1 ea 02 8d 04 d2 03 c0 8b d1 2b d0 8a 44 15 ?? 30 04 31 41 3b cf 72 e1 05 00 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Alinaos_F_2147686829_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Alinaos.F"
        threat_id = "2147686829"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Alinaos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%sntfs.dat" ascii //weight: 1
        $x_1_2 = ".\\pipe\\spark" ascii //weight: 1
        $x_1_3 = {75 70 64 61 74 65 69 6e 74 65 72 76 61 6c 3d [0-8] 63 61 72 64 69 6e 74 65 72 76 61 6c 3d}  //weight: 1, accuracy: Low
        $x_1_4 = "http://%s:%d{[!4!]" ascii //weight: 1
        $x_1_5 = {73 79 73 74 65 6d 00 00 77 69 6e 64 65 66 65 6e 64 65 72 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_6 = "win-firewall.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Alinaos_G_2147689101_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Alinaos.G"
        threat_id = "2147689101"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Alinaos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {75 70 64 61 74 65 69 6e 74 65 72 76 61 6c 3d [0-8] 63 61 72 64 69 6e 74 65 72 76 61 6c 3d}  //weight: 3, accuracy: Low
        $x_3_2 = {6c 6f 67 3d 31 [0-8] 7b 5b 21 31 37 21 5d 7d 7b 5b 21 31 38 21 5d 7d [0-8] 6c 6f 67 3d 30 [0-8] 7b 5b 21 31 37 21 5d 7d 7b 5b 21 31 39 21 5d 7d}  //weight: 3, accuracy: Low
        $x_1_3 = "%sntfs.dat" ascii //weight: 1
        $x_1_4 = "http://%s:%d{[!4!]" ascii //weight: 1
        $x_1_5 = "win-firewall.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Alinaos_A_2147691815_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Alinaos.gen!A"
        threat_id = "2147691815"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Alinaos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 6c 69 6e 61 20 76 01 00 2e 01 00 00}  //weight: 5, accuracy: Low
        $x_2_2 = {61 63 74 3d 25 73 26 62 3d 25 73 26 63 3d 25 73 26 76 3d 25 73 26 25 73 3d 00}  //weight: 2, accuracy: High
        $x_2_3 = {28 28 28 25 3f 5b 42 62 ef bf bd 60 5d 3f 29 5b 5e 5b 41 2d 5a 61 2d 7a 5c 73 5d 7b 30 2c 32 36 7d 2f 5b 41 2d 5a 61 2d 7a 5c 73 5d 7b 30 2c 32 36 7d 5c 5e 28 31 5b 32 2d 39 5d 29 28 30 5b 31 2d 39 5d 7c 31 5b 30 2d 32 5d 29 5b 30 2d 39 5c 73 5d 7b 33 2c 35 30 7d 5c 3f 29}  //weight: 2, accuracy: High
        $x_2_4 = "((%?[Bb]?)[0-9]{13,19}\\^[A-Za-z\\s]{0,26}/[A-Za-z\\s]{0,26}\\^(1[2-9])(0[1-9]|1[0-2])[0-9\\s]{3,50}\\?)" ascii //weight: 2
        $x_2_5 = {61 6c 69 6e 61 3d 00}  //weight: 2, accuracy: High
        $x_2_6 = {2f 75 70 6c 6f 61 64 2e 70 68 70 00}  //weight: 2, accuracy: High
        $x_2_7 = {77 6f 6e 74 20 6b 69 6c 6c 20 72 65 67 69 73 74 72 79 20 72 65 63 6f 72 64 20 66 6f 72 20 6e 6f 77 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Alinaos_B_2147691816_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Alinaos.gen!B"
        threat_id = "2147691816"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Alinaos"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 5c 2e 5c 70 69 70 65 5c 73 70 61 72 6b 00}  //weight: 2, accuracy: High
        $x_2_2 = {5c 5c 2e 5c 70 69 70 65 5c 45 61 67 6c 65 00}  //weight: 2, accuracy: High
        $x_2_3 = {7b 5b 21 31 32 21 5d 7d 7b 5b 21 31 30 21 5d 7d 68 74 74 70 3a 2f 2f 25 73 3a 25 64 7b 5b 21 34 21 5d 7d 00}  //weight: 2, accuracy: High
        $x_2_4 = {49 6e 66 6f 50 61 74 68 2e 31 20 53 70 61 72 6b 20 76 00}  //weight: 2, accuracy: High
        $x_2_5 = {7b 5b 21 33 37 21 5d 7d 7b 5b 21 33 35 21 5d 7d 7b 5b 21 34 21 5d 7d 7b 5b 21 33 38 21 5d 7d 30 78 25 78 2c 7b 5b 21 33 39 21 5d 7d 30 78 25 78 2e 00}  //weight: 2, accuracy: High
        $x_2_6 = {75 70 64 61 74 65 69 6e 74 65 72 76 61 6c 3d 00}  //weight: 2, accuracy: High
        $x_2_7 = {63 61 72 64 69 6e 74 65 72 76 61 6c 3d 00}  //weight: 2, accuracy: High
        $x_2_8 = "win-firewall.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Alinaos_2147692913_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Alinaos"
        threat_id = "2147692913"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Alinaos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 00 77 00 6f 00 72 00 64 00 00 2d 44 00 48 00 43 00 50 00 48 00 61 00 6e 00 64 00 6c 00 65 00 72 00 32 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 00 19 44 00 48 00 43 00 50 00 20 00 48 00 61 00 6e 00 64 00 6c 00 65 00 72 00 00 17 43 00 65 00 6e 00 74 00 65 00 72 00 50 00 6f 00 69 00 6e 00 74 00 00 07 31 00 2e 00}  //weight: 1, accuracy: High
        $x_1_2 = {75 00 6e 00 69 00 63 00 65 00 6e 00 74 00 65 00 72 00 2e 00 62 00 61 00 74 00 0d 00 0a 00 00 0d 65 00 78 00 69 00 74 00 0d 00 0a 00 00 1b 75 00 6e 00 69 00 63 00 65 00 6e 00 74 00 65 00 72 00 2e 00 62 00 61 00 74 00 00 13 2f 00 43 00 20 00 63 00 61 00 6c 00 6c 00 20 00 22 00 00 1f 5c 00 75 00 6e 00 69 00 63 00 65 00 6e 00 74 00 65 00 72 00 2e 00 62 00 61 00 74 00 22 00 00 07 7b 00}  //weight: 1, accuracy: High
        $x_1_3 = {6e 00 61 00 6d 00 65 00 3d 00 22 00 75 00 73 00 65 00 72 00 66 00 69 00 6c 00 65 00 22 00 3b 00 01 1d 66 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 3d 00 22 00 7b 00 30 00 7d 00 22 00 00 09 2e 00 74 00 78 00 74 00 00 4d 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2d 00 54 00 79 00 70 00 65 00 3a 00 20 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2f 00 6f 00 63 00 74 00 65 00 74 00 2d 00 73 00 74 00 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {5b 00 2f 00 32 00 30 00 30 00 2f 00 5d 00 00 07 5b 00 69 00 5d 00 00 09 5b 00 2f 00 69 00 5d 00 00 07 5b 00 6b 00 5d 00 00 09 5b 00 2f 00 6b 00 5d 00 00 0f 5b 00 2f 00 34 00 30 00 31 00 2f 00 5d 00 00 17 40 00 65 00 63 00 68 00 6f 00 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

