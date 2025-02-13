rule TrojanSpy_Win32_Nivdort_A_2147680200_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Nivdort.A"
        threat_id = "2147680200"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nivdort"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 fc c1 fa 04 33 d1 03 55 f8 89 55 f8 81 7d f0 ?? ?? 00 00 75 13}  //weight: 10, accuracy: Low
        $x_10_2 = {89 4d e8 0f 10 ?? ?? b0 50 00 8b 55 e4}  //weight: 10, accuracy: Low
        $x_10_3 = {4f 00 83 c1 59 51 e8 ?? ?? ?? 00 83 c4 04 a3}  //weight: 10, accuracy: Low
        $x_1_4 = {74 3a 8b 4d f0 8b 55 e4 8d 84 0a ?? ?? ?? ?? 33 45 f8 89 45 f8 8b 4d f4 0f be 11 8b 45 e8 0f be 08 33 ca 8b 55 e8 88 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Nivdort_A_2147680312_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Nivdort.gen!A"
        threat_id = "2147680312"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nivdort"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 01 00 00 75 ?? 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 01 6a 00 ff 15 ?? ?? ?? 00 8b ?? 08 89 04}  //weight: 1, accuracy: Low
        $x_1_3 = {fc 6a 14 ff 15 ?? ?? ?? 00 8b 55 ?? 83 ?? 01}  //weight: 1, accuracy: Low
        $x_1_4 = {68 10 27 00 00 8b ?? 08 8b ?? ?? ?? ?? ?? 00 ?? ff 15 ?? ?? ?? 00 8b}  //weight: 1, accuracy: Low
        $x_1_5 = {68 00 06 00 00 68 ?? ?? ?? 00 e8 ?? ?? ?? ?? 83 c4 08 89 45 ?? 8b}  //weight: 1, accuracy: Low
        $x_1_6 = {89 4d e8 8b 55 fc 8b 02 33 45 f4 8b 4d fc 89 01 8b 55 f0 83 c2 01 89 55 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Nivdort_E_2147681427_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Nivdort.gen!E"
        threat_id = "2147681427"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nivdort"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ea 01 89 55 [0-16] 81 7d ?? 2c 01 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 59 50 6a 00 8b [0-10] e8 ?? ?? ?? 00 83 c4 0c}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 e8 0f be 08 33 ca 8b 55 e8 88 0a 8b 45 f8 83 c0 01 89 45 f8}  //weight: 1, accuracy: High
        $x_1_4 = {83 c4 04 8b 4d f8 c1 e1 ?? 8b 55 f8 2b d1 8b 45 fc c1 f8 ?? 03 d0}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 4d 08 89 04 8d ?? ?? 51 00 8b 55 e4 c1 fa 06 69 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Nivdort_T_2147686048_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Nivdort.T"
        threat_id = "2147686048"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nivdort"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 11 8b 45 ?? 0f be 08 33 ca 8b 55 ?? 88 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 34 68 30 ?? 44 00 e8 ?? ?? ?? ?? 83 c4 08}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 44 68 d8 ?? 44 00 e8 ?? ?? ?? ?? 83 c4 08}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 20 68 80 ?? 44 00 e8 ?? ?? ?? ?? 83 c4 08}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 7e 68 c0 ?? 44 00 e8 ?? ?? ?? ?? 83 c4 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Nivdort_DB_2147708541_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Nivdort.DB"
        threat_id = "2147708541"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nivdort"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c 68 90 5f 01 00 ff 15 ?? ?? 44 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 68 05 0d 00 00 ff 15 ?? ?? 44 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 00 68 e8 03 00 00 ff 15 ?? ?? 44 00 (0f|a1) ?? ?? (44|45) 00}  //weight: 1, accuracy: Low
        $x_1_4 = {00 68 d0 07 00 00 ff 15 ?? ?? 44 00}  //weight: 1, accuracy: Low
        $x_1_5 = {68 50 c3 00 00 ff 15 ?? ?? 44 00 (c7 05|b8)}  //weight: 1, accuracy: Low
        $x_1_6 = {68 00 50 00 00 8d 85 f8 af ff ff 50 57 ff 15 ?? ?? 44 00}  //weight: 1, accuracy: Low
        $x_1_7 = {68 10 27 00 00 [0-16] ff 15 ?? ?? 44 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Nivdort_DH_2147708705_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Nivdort.DH"
        threat_id = "2147708705"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nivdort"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 50 03 88 51 fe 0f b6 50 02 88 51 ff 8b 10 c1 ea 08 88 11 0f b6 10 88 51 01 83 c0 04 83 c1 04 83 ee 01 75 da}  //weight: 2, accuracy: High
        $x_2_2 = {79 05 49 83 c9 e0 41 0f b6 84 0c ?? ?? 00 00 99 bd 1a 00 00 00 f7 fd 80 c2 61 88 94 34 ?? ?? 00 00 46 3b f7 75}  //weight: 2, accuracy: Low
        $x_2_3 = {77 61 74 63 68 5f 64 6f 67 5f 6e 61 6d 65 2e 65 78 65 [0-16] 2f 69 6e 64 65 78 2e 70 68 70 3f 64 61 74 61 3d [0-16] 4c 4f 43 4b [0-16] 77 62}  //weight: 2, accuracy: Low
        $x_1_4 = "ADRIANCOPILULMINUNESIFLORINSALAM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Nivdort_DR_2147711696_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Nivdort.DR"
        threat_id = "2147711696"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nivdort"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 18 3b 44 24 1c 0f [0-32] 8b 44 24 14 0f b6 00 8b 4c 24 18 0f b6 11 31 c2 88 d3 88 19}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 41 08 06 00 00 00 c7 41 04 01 00 00 00 c7 01 02 00 00 00 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Nivdort_DR_2147711696_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Nivdort.DR"
        threat_id = "2147711696"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nivdort"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/index.php?is_p2penv=ZGFuZ2Vsby5hc2VuY2lvQGktbmV0cGVydS5jb20ucGUJ" ascii //weight: 1
        $x_1_2 = "/index.php?is_p2penv=ZGFuZ2Vsby5hc2VuY2lvQGktbmV0cGVydS5jb20ucGUJ" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Nivdort_EC_2147711770_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Nivdort.EC"
        threat_id = "2147711770"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nivdort"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 04 01 8b 4c 24 [0-10] 0f b6 31 31 c6 89 f0 88 c2 88 11}  //weight: 2, accuracy: Low
        $x_1_2 = {89 e1 c7 01 e5 08 00 00 ff d0 83 ec 04}  //weight: 1, accuracy: High
        $x_1_3 = {89 e1 c7 01 f4 01 00 00 ff d0 83 ec 04}  //weight: 1, accuracy: High
        $x_1_4 = {89 e2 c7 02 c3 62 01 00 89 44 24 ?? ff d1 83 ec 04}  //weight: 1, accuracy: Low
        $x_1_5 = {89 e1 c7 01 1f 04 00 00 ff d0 83 ec 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Nivdort_EJ_2147717223_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Nivdort.EJ"
        threat_id = "2147717223"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nivdort"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 00 00 c0 00 e8 ?? ?? 00 00 83 c4 04 [0-16] 8b 8d [0-16] 51 68 00 00 30 00 8b 95 [0-16] 52 e8}  //weight: 2, accuracy: Low
        $x_1_2 = {ab d1 cb eb [0-16] 8b 4d 0c eb}  //weight: 1, accuracy: Low
        $x_1_3 = {52 68 00 60 00 00 68 ?? ?? ?? 00 8b 85 ?? ?? ff ff 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

