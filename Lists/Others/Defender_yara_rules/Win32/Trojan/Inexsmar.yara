rule Trojan_Win32_Inexsmar_A_2147696930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Inexsmar.A"
        threat_id = "2147696930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Inexsmar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {52 49 68 35 4d 57 64 69 6a 62 45 30 29 5a 24 5a 17 5b 4d 69 61 57 69 6e 3f 5b 57 5b 3a 44 62 16 63 28 6f 52 52 65 52 58 64 62 6c 28 6a 29 69 00}  //weight: 2, accuracy: High
        $x_2_2 = {65 64 64 59 6d 16 63 59 57 6a 62 62 6a 59 65 5b 63 29 62 5a 16 5c 16 5f 69 55 5f 65 28 5b 69 5b 68 5b 00}  //weight: 2, accuracy: High
        $x_2_3 = {3b 6a 52 46 63 5b 37 48 46 3e 49 65 4a 3a 68 52 52 3f 45 69 68 3a 26 68 65 3f 64 48 6f 4d 5b 48 59 62 69 49 6a 5b 37 39 44 3b 52 69 57 39 00}  //weight: 2, accuracy: High
        $x_1_4 = {2c 62 61 5a 62 69 24 64 5e 2a 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {1b 1b 37 37 4a 37 3a 46 46 00}  //weight: 1, accuracy: High
        $x_1_6 = {6f 6e 66 63 57 39 5b 5b 52 24 30 66 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

