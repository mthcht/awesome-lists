rule Trojan_Win32_Pleror_A_2147678471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pleror.A"
        threat_id = "2147678471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pleror"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 50 0c 80 ea 01 72 0c 74 18 fe ca 74 22 fe ca 74 2c eb 37 ba}  //weight: 2, accuracy: High
        $x_1_2 = {62 00 61 00 69 00 64 00 75 00 2e 00 63 00 6f 00 6d 00 2f 00 00 00 32 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 2e 00 68 00 6b 00 2f 00 00 00 2a 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 73 00 6f 00 67 00 6f 00 75 00 2e 00 63 00 6f 00 6d 00 2f 00 00 00 28 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 73 00 6f 00 73 00 6f 00 2e 00 63 00 6f 00 6d 00 2f 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {6b 69 6c 6c 6d 65 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 74 74 72 69 62 20 2d 68 20 2d 72 20 2d 61 20 2d 73 20 22 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

