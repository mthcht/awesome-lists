rule Trojan_Win32_Sabresac_A_2147711159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabresac.A!bit"
        threat_id = "2147711159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabresac"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {77 00 77 00 77 00 2e 00 62 00 61 00 69 00 64 00 75 00 2e 00 63 00 6f 00 6d 00 2f 00 [0-96] 26 00 77 00 64 00 3d 00 69 00 70 00 31 00 33 00 38 00}  //weight: 10, accuracy: Low
        $x_10_2 = {62 00 6c 00 6f 00 67 00 2e 00 63 00 73 00 64 00 6e 00 2e 00 6e 00 65 00 74 00 2f 00 2f [0-64] 2f 00 2f 00 61 00 72 00 74 00 69 00 63 00 6c 00 65 00 2f 00 2f 00 64 00 65 00 74 00 61 00 69 00 6c 00 73 [0-32] 73 61 62 65 72 73 74 61 72 74}  //weight: 10, accuracy: Low
        $x_10_3 = {6b 00 61 00 62 00 79 00 2e 00 00 00 6e 00 64 00 33 00 32 00 2e 00}  //weight: 10, accuracy: High
        $x_1_4 = {63 00 63 00 6c 00 65 00 61 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 00 00 63 00 63 00 6c 00 65 00 61 00 6e 00 65 00 72 00}  //weight: 1, accuracy: High
        $x_1_5 = {45 00 78 00 63 00 61 00 6c 00 69 00 62 00 75 00 72 00 53 00 76 00 63 00 42 00 00 00 77 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 62 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

