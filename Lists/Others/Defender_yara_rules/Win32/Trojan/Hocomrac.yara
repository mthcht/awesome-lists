rule Trojan_Win32_Hocomrac_A_2147652339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hocomrac.A"
        threat_id = "2147652339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hocomrac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {60 83 7d 18 03 74 14 83 7d 18 04 74 0e 83 7d 18 02 74 08 83 7d 18 05 74 02 eb 65}  //weight: 3, accuracy: High
        $x_2_2 = {99 ac 8a c8 3c 0f 74 0f 66 81 7e ff cd 20 75 0a 46 ad}  //weight: 2, accuracy: High
        $x_2_3 = {83 e8 05 03 5d f8 c7 03 e9 00 00 00 43 89 03}  //weight: 2, accuracy: High
        $x_1_4 = {2d 43 68 6f 63 6f 63 72 65 61 6d 7d 00}  //weight: 1, accuracy: High
        $x_1_5 = {24 24 63 6f 6e 66 69 67 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 73 76 68 6f 73 74 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 73 76 68 6f 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

