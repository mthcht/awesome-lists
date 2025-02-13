rule Trojan_Win32_Popool_B_2147729043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Popool.B"
        threat_id = "2147729043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Popool"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {38 38 00 00 68 65 6c 6c 6f 25 73 00 6e 6f 20 75 73 65 00 00 3a 00 00 00 68 74 74 70 00 00 00 00 30 00 00 00 68 74 74 70 73 00 00 00 6f 70 65 6e 09 00 00 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 29 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Popool_A_2147729044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Popool.A"
        threat_id = "2147729044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Popool"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 00 65 00 6d 00 6f 00 6e 00 4d 00 75 00 74 00 65 00 78 00 25 00 64 00 00 [0-60] 25 00 73 00 5f 00 25 00 73 00 25 00 64 00 00 00 70 00 72 00 6f 00 78 00 79 00 2e 00 6c 00 6f 00 67 00 00 00 2f 00 3f 00 69 00 64 00 3d 00 25 00 73 00 26 00 69 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {69 00 72 00 00 00 00 00 61 00 6b 00 00 00 00 00 78 00 74 00 00 00 00 00 6b 00 73 00 00 00 00 00 78 00 65 00 00 00 00 00 76 00 61 00 00 00 00 00 79 00 7a 00 00 00 00 00 63 00 75 00 00 00 00 00 6b 00 77 00 00 00 00 00 75 00 63 00 00 00 00 00 68 00 72 00 00 00 00 00 63 00 73 00 00 00 00 00 65 00 67 00 00 00 00 00 78 00 6d 00 00 00 00 00 73 00 6b 00 00 00 00 00 6c 00 74 00 00 00 00 00 25 00 73 00 5c 00 72 00 61 00 72 00 2e 00 65 00 78 00 65 00 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

