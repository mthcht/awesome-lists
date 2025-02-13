rule Trojan_Win32_Mustrat_A_2147684943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mustrat.A"
        threat_id = "2147684943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mustrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 6d 69 6e 65 72 64 2e 65 78 65 00 6c 69 62 63 75 72 6c 2d 34 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = "stratum+tcp:" ascii //weight: 1
        $x_1_3 = {25 54 45 4d 50 25 5c 77 69 6e 64 6f 77 73 00 5c 77 69 6e 73 79 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_3_4 = {c7 44 24 10 40 00 00 00 c7 44 24 0c 00 30 00 00 8b 95 ?? ?? ?? ?? 8b 42 50 89 44 24 08 8b 42 34 89 44 24 04 8b 85 ?? ?? ?? ?? 89 04 24 e8}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

