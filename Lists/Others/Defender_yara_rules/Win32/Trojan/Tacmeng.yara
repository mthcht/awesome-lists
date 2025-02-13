rule Trojan_Win32_Tacmeng_A_2147667362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tacmeng.A"
        threat_id = "2147667362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tacmeng"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {3a c2 74 08 8a 46 fe 4e 3a c2 75 f8 8b}  //weight: 2, accuracy: High
        $x_2_2 = {88 5c 24 10 f3 ab 66 ab aa b9 40 00 00 00 33 c0 8d 7c 24 11 6a 54 f3 ab 66 ab aa 8d}  //weight: 2, accuracy: High
        $x_2_3 = {85 d2 74 2d 8b fa 83 c9 ff f2 ae f7 d1 49 74 21 8b fa 83 c9 ff f2 ae f7 d1 2b f9 8b c1 8b f7 8d}  //weight: 2, accuracy: High
        $x_2_4 = {52 50 3f 4d 52 00 7f 01 5a 51 aa 01 89}  //weight: 2, accuracy: High
        $x_1_5 = {50 72 6f 64 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_6 = {50 72 6f 65 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_7 = {63 74 66 6d 6f 6e 5c 63 74 66 6d 6f 6e 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_8 = {5f 4f 6e 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_9 = {5f 46 72 61 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_10 = {5f 42 79 5f 46 69 66 74 68 5f 00}  //weight: 1, accuracy: High
        $x_1_11 = {63 63 73 76 63 68 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_12 = {43 72 74 52 75 6e 54 69 6d 65 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_2_13 = "nctadbldla.edalcln" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

