rule Trojan_Win32_Hyrax_B_2147964682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hyrax.B"
        threat_id = "2147964682"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hyrax"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 50 75 6c 73 65 20 53 65 63 75 72 65 5c 43 6f 6e 6e 65 63 74 69 6f 6e 53 74 6f 72 65 5c 63 6f 6e 6e 73 74 6f 72 65 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 69 3a 20 25 73 0a 55 73 65 72 3a 20 25 73 0a 50 61 73 73 3a 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {4f 53 54 20 2f 69 6e 63 6f 6d 65 5f 73 68 69 74 20 48 54 54 50 2f 31 2e 30 0d 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

