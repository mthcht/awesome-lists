rule PWS_Win32_Makuha_A_2147688999_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Makuha.A"
        threat_id = "2147688999"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Makuha"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "name=%s&pass=%s&ver=%s&mac=%s&id=%s" ascii //weight: 1
        $x_1_2 = "QQ=%s&PWD=%s&Hacker=%s" ascii //weight: 1
        $x_2_3 = "\\Bin\\QQ.exe" ascii //weight: 2
        $x_2_4 = "\\Bin\\TM.exe" ascii //weight: 2
        $x_2_5 = {00 5c 54 65 6e 63 65 6e 74 20 46 69 6c 65 73}  //weight: 2, accuracy: High
        $x_5_6 = {c6 44 24 1c 41 c6 44 24 1d 46 c6 44 24 1e 24 c6 44 24 1f 25 c6 44 24 20 28 c6 44 24 21 34 c6 44 24 22 79 c6 44 24 23 00}  //weight: 5, accuracy: High
        $x_1_7 = {8a 04 2a 33 d2 8a 11 03 f8 03 fa 81 e7 ff 00 00 80 79 08 4f 81 cf 00 ff ff ff 47}  //weight: 1, accuracy: High
        $x_6_8 = {c6 44 24 24 3a c6 44 24 25 38 88 54 24 27 88 54 24 2a c6 44 24 2b 6c c6 44 24 2c 69 c6 44 24 2d 6e 88 44 24 2e c6 44 24 2f 61 c6 44 24 30 73 c6 44 24 31 70 c6 44 24 32 00}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

