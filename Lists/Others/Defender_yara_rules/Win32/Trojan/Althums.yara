rule Trojan_Win32_Althums_A_2147679181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Althums.A"
        threat_id = "2147679181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Althums"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 2e 00 69 00 6e 00 69 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 00 68 00 75 00 6d 00 62 00 63 00 61 00 63 00 68 00 65 00 2e 00 64 00 62 00 00 00}  //weight: 1, accuracy: High
        $x_10_3 = {4d 00 73 00 48 00 65 00 6c 00 70 00 43 00 65 00 6e 00 74 00 65 00 72 00 2e 00 69 00 64 00 78 00 00 00}  //weight: 10, accuracy: High
        $x_10_4 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 00 00 00 00 47 (65 63|6f 7a 69 6c) 5f 25 6c 64 2f 25 73 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

