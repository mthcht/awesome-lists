rule Trojan_Win32_Bnserv_A_2147631833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bnserv.A"
        threat_id = "2147631833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bnserv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 62 00 6e 00 73 00 65 00 72 00 76 00 34 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {31 72 65 70 6c 79 46 69 6e 69 73 68 65 64 28 51 4e 65 74 77 6f 72 6b 52 65 70 6c 79 2a 29 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 74 74 70 3a 2f 2f [0-32] 2f 70 6c 61 6e ?? 2e 78 6d 6c 00}  //weight: 1, accuracy: Low
        $x_5_4 = {26 61 63 74 69 6f 6e 3d 67 65 74 26 69 64 3d 00 72 65 73 2e 70 68 70 3f 6b 65 79 3d 00 00 00 00 63 61 70 63 68 61 4b 65 79}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

