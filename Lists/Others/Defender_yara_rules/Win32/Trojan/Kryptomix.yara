rule Trojan_Win32_Kryptomix_2147733611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptomix"
        threat_id = "2147733611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptomix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 00 65 00 76 00 69 00 63 00 65 00 43 00 6f 00 6e 00 66 00 69 00 67 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 2e 00 76 00 62 00 73 00 00 00 2e 00 76 00 62 00 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 00 00 25 00 6c 00 73 00 2e 00 6c 00 6e 00 6b 00 00 00 25 00 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 41 00 6e 00 74 00 69 00 53 00 70 00 79 00 77 00 61 00 72 00 65 00 00 00 00 00 00 00 00 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00}  //weight: 1, accuracy: High
        $x_2_4 = {25 00 6c 00 73 00 5c 00 77 00 69 00 6e 00 6d 00 67 00 72 00 2e 00 74 00 78 00 74 00 00 00 00 00 25 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 00 00 28 00 78 00 38 00 36 00 29 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

