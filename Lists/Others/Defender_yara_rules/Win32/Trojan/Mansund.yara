rule Trojan_Win32_Mansund_2147608825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mansund"
        threat_id = "2147608825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mansund"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 42 35 21 f0 1f 76 62 36 63 68 73 2e 64 6c 6c 00 00 00 00 2a 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 00 04 08 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_2_2 = {2a 00 5c 00 41 00 43 00 3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 5c 00 4c 68 62 97 5c 00 01 00 00 2e 00 01 00 00 01 5c 00 6d 00 73 00 5c 00 03 04 06 08 2f 54 a8 52 2c 7b 00 4e 2a 4e 0d 67 a1 52 2f 54 a8 52 5c 00 e5 5d 0b 7a 31 00 2e 00 76 00 62 00 70}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

