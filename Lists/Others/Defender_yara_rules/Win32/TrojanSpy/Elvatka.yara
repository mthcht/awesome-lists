rule TrojanSpy_Win32_Elvatka_A_2147689961_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Elvatka.A"
        threat_id = "2147689961"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Elvatka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PROTOCAL_USE_SOCKET" ascii //weight: 1
        $x_1_2 = {55 70 64 61 74 65 49 6d 70 6f 72 74 54 61 62 6c 65 41 64 64 72 65 73 73 20 6f 6b 21 00}  //weight: 1, accuracy: High
        $x_1_3 = {62 65 67 69 6e 20 43 72 65 61 74 65 46 69 6c 65 41 20 70 61 74 68 20 69 73 20 25 73 21 00}  //weight: 1, accuracy: High
        $x_1_4 = {45 6c 65 76 61 74 65 44 6c 6c 5f 78 38 36 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_5 = "SHFileOperation [%s] succeeds!" wide //weight: 1
        $x_1_6 = {25 00 73 00 5c 00 75 00 70 00 64 00 61 00 74 00 65 00 25 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Elvatka_B_2147690235_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Elvatka.B"
        threat_id = "2147690235"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Elvatka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 04 16 32 c1 34 ?? 88 02 41 42 66 83 f9 ?? 72 ef}  //weight: 5, accuracy: Low
        $x_1_2 = {55 70 64 61 74 65 49 6d 70 6f 72 74 54 61 62 6c 65 41 64 64 72 65 73 73 20 6f 6b 21 00}  //weight: 1, accuracy: High
        $x_1_3 = {62 65 67 69 6e 20 43 72 65 61 74 65 46 69 6c 65 41 20 70 61 74 68 20 69 73 20 25 73 21 00}  //weight: 1, accuracy: High
        $x_1_4 = "du.phistar.pw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

