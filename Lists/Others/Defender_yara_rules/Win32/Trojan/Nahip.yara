rule Trojan_Win32_Nahip_A_2147678939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nahip.A"
        threat_id = "2147678939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nahip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4e 79 05 be 18 00 00 00 8a 54 34 ?? 8a 1c 01 32 da 88 1c 01 41 3b cf 7c e7}  //weight: 2, accuracy: Low
        $x_1_2 = {b3 2e b1 78 b2 72 3b c7 89 7d fc c7 85 98 fe ff ff 28 01 00 00 c6 45 d0 77 c6 45 d1 69 c6 45 d3 6c}  //weight: 1, accuracy: High
        $x_1_3 = {b3 65 8d 4c 24 48 c6 44 24 10 77 85 c9 c6 44 24 11 69 c6 44 24 12 6e c6 44 24 13 6c}  //weight: 1, accuracy: High
        $x_1_4 = {72 00 75 00 6e 00 61 00 73 00 00 00 25 73 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

