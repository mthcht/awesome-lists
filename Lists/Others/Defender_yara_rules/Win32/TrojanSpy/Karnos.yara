rule TrojanSpy_Win32_Karnos_A_2147661314_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Karnos.A"
        threat_id = "2147661314"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Karnos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 a6 0f 84 ?? ?? ?? ?? b9 0a 00 00 00 8d 7c 24 ?? f3 ab 66 ab b9 0a 00 00 00 8b ?? 8d 7c 24 ?? 68 ?? ?? ?? ?? f3 a5 66 a5 8b 35 ?? ?? ?? ?? 8d 4c 24 ?? 51 ff d6 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 35 31 77 61 6e 61 2e 63 6f 6d 2f 74 6a 2f 73 65 74 2e 61 73 70 00 00 00 00 73 3d 25 73 26 68 3d 25 64 00 00 00 68 74 74 70 3a 2f 2f 70 6c 75 67 69 6e 2e 39 32 74 61 6f 6a 69 6e 2e 63 6f 6d 2f 70 6c 75 67 69 6e 2f 61 63 63 65 70 74 2f 73 65 61 72 63 68 6c 6f 67 00 00 64 61 74 61 3d 25 73 00 7b 22 68 6f 73 74 22 3a 25 75 2c 22 6b 65 79 22 3a 22 25 73 22 2c 20 22 69 65 6e 61 6d 65 22 3a 22 [0-5] 22 7d}  //weight: 1, accuracy: Low
        $x_1_3 = {62 69 6e 67 2e 63 6f 6d 00 00 00 00 67 6f 6f 67 6c 65 00 00 73 6f 67 6f 75 2e 63 6f 6d 00 00 00 73 6f 73 6f 2e 63 6f 6d 00 00 00 00 62 61 69 64 75 2e 63 6f 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Karnos_B_2147686817_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Karnos.B"
        threat_id = "2147686817"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Karnos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tieba_name" ascii //weight: 1
        $x_1_2 = "mon_web_keyword" ascii //weight: 1
        $x_1_3 = "\\taojin\\2.0\\iespy" ascii //weight: 1
        $x_1_4 = {62 69 6e 67 2e 63 6f 6d 00 00 00 00 67 6f 6f 67 6c 65 00 00 73 6f 67 6f 75 2e 63 6f 6d 00 00 00 73 6f 73 6f 2e 63 6f 6d 00 00 00 00 62 61 69 64 75 2e 63 6f 6d}  //weight: 1, accuracy: High
        $x_1_5 = {74 61 6f 6a 69 6e 2e 63 6f 6d 2f 70 6c 75 67 69 6e 2f 61 63 63 65 70 74 2f 73 65 61 72 63 68 6c 6f 67 [0-16] 64 61 74 61 3d 25 73 00 7b 22 68 6f 73 74 22 3a 25 75 2c [0-32] 22 6b 65 79 22 3a 22 25 73 22 2c 20 22 69 65 6e 61 6d 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

