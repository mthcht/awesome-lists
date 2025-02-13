rule TrojanSpy_Win32_Iletraskod_A_2147705984_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Iletraskod.A"
        threat_id = "2147705984"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Iletraskod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "lcreventos.ddns.net" wide //weight: 4
        $x_2_2 = {49 45 54 61 73 6b 2e 64 6c 6c 00 41 63 74 69 76 65}  //weight: 2, accuracy: High
        $x_2_3 = {43 6f 6e 6e 65 63 74 42 61 6e 6b 00 44 69 73 63 6f 6e 6e 65 63 74}  //weight: 2, accuracy: High
        $x_2_4 = "#VERSION-LC-2.0.0.7" ascii //weight: 2
        $x_1_5 = {85 c0 74 2e f6 43 1c 01 75 1d 80 7b 40 00 74 17 8b 0d ?? ?? ?? 00 b2 01}  //weight: 1, accuracy: Low
        $x_1_6 = {3a 50 40 74 1a f6 40 1c 10 75 06 f6 40 1c 01 74 03 88 50 40 f6 40 1c 01 75 05 8b 08 ff 51 48}  //weight: 1, accuracy: High
        $x_1_7 = {eb f0 ff 45 f0 83 7d f0 37 0f 85 43 ff ff ff 33 c0 5a 59 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Iletraskod_B_2147706363_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Iletraskod.B"
        threat_id = "2147706363"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Iletraskod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 45 54 61 73 6b 2e 64 6c 6c 00 41 63 74 69 76 65}  //weight: 1, accuracy: High
        $x_1_2 = {43 6f 6e 6e 65 63 74 42 61 6e 6b 00 44 69 73 63 6f 6e 6e 65 63 74}  //weight: 1, accuracy: High
        $x_1_3 = {23 56 45 52 53 49 4f 4e 2d 50 57 2d 32 2e 30 2e 30 2e 30 00}  //weight: 1, accuracy: High
        $x_1_4 = {23 00 49 00 44 00 43 00 6c 00 49 00 45 00 4e 00 54 00 2d 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {23 00 42 00 41 00 4e 00 4b 00 2d 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {23 00 55 00 53 00 45 00 52 00 2d 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {23 00 42 00 52 00 4f 00 57 00 53 00 45 00 52 00 2d 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {23 00 50 00 4c 00 55 00 47 00 49 00 4e 00 2d 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {23 00 50 00 43 00 4e 00 41 00 4d 00 45 00 2d 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {8b 45 08 8b d0 8b 45 0c f0 87 02 5d c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

