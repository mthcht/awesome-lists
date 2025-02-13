rule TrojanSpy_Win32_Seclining_A_2147610315_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Seclining.gen!A"
        threat_id = "2147610315"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Seclining"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {50 68 d9 03 00 00 68 ?? ?? ?? ?? 8b 8d ?? ?? ff ff 51 8b 55 dc 52 ff 15 ?? ?? ?? ?? 85 c0 74 09 81 7d fc d9 03 00 00 74 07}  //weight: 5, accuracy: Low
        $x_5_2 = {e8 00 00 00 00 5d 81 ed 05 00 00 00 b8 59 00 00 00 01 e8 50 b8 44 33 22 11 ff d0 93 b8 ed 00 00 00}  //weight: 5, accuracy: High
        $x_1_3 = {74 79 70 65 3d 70 61 73 73 77 6f 72 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {4c 6f 67 53 65 6e 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {47 52 42 4d 41 47 49 43 00}  //weight: 1, accuracy: High
        $x_1_6 = {64 6f 69 63 61 72 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Seclining_C_2147610316_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Seclining.gen!C"
        threat_id = "2147610316"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Seclining"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 ff 8a 45 ff c0 c8 02 88 45 ff 8a 45 ff 42 81 fa 00 92 00 00 88 01 7c da}  //weight: 1, accuracy: High
        $x_1_2 = {78 6b 6c 30 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Seclining_D_2147610317_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Seclining.gen!D"
        threat_id = "2147610317"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Seclining"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 6c 6f 67 73 65 6e 64 2e 64 6c 6c 00 4c 6f 67 53 65 6e 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {69 64 3d 25 73 26 74 79 70 65 3d 25 73 26 63 6f 6d 6d 65 6e 74 3d 25 73 26 6c 6f 67 3d 25 73 00}  //weight: 1, accuracy: High
        $x_3_3 = {75 49 c7 45 d4 71 7f 90 3c c7 45 cc 86 0a 51 4d c7 45 d0 24 2d f8 4a c7 45 c8 36 4a b3 23 c7 45 d8 ae 4a 77 53 8b 4d cc 0f af 4d d0 0b 4d c8 0b 4d d8 89 4d d4 83 7d 0c 00 74 09}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

