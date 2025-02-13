rule Trojan_Win32_Uncrre_A_2147710542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Uncrre.A"
        threat_id = "2147710542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Uncrre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {23 53 74 72 69 6e 67 73 00 00 00 00 1c 03 00 00 08 00 00 00 23 55 53 00 24 03 00 00 10 00 00 00 23 47 55 49 44 00 00 00 34 03 00 00 64 00 00 00 23 42 6c 6f 62 00 00 00 00 00 00 00 02 00 00 01}  //weight: 1, accuracy: High
        $x_1_2 = {20 00 21 00 5d 00 26 00 29 00 5d 00 1c 00 31 00 5d 00 2b 00 09 00 5d 00 1c 00 2e 00 0b 00 30 00 2e 00 13 00 39 00 2e 00 1b 00 42 00 32 01 00 01 03 00 43 00 01 00 00 01 05 00 50 00 01 00 04 80}  //weight: 1, accuracy: High
        $x_1_3 = {2e 64 6c 6c 00 57 69 6e 33 32 00 57 69 6e 33 32 46 75 6e 63 74 69 6f 6e 73 00 6d 73 63 6f 72 6c 69 62 00 53 79 73 74 65 6d 00 4f 62 6a 65 63 74 00 43 72 65 61 74 65 54 68 72 65 61 64 00 56 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

