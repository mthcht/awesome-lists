rule Trojan_Win32_Paserut_A_2147729377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Paserut.A"
        threat_id = "2147729377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Paserut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 [0-8] 20 00 2d 00 64 00 65 00 63 00 6f 00 64 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 [0-4] 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27}  //weight: 1, accuracy: Low
        $x_1_3 = {61 00 64 00 64 00 2d 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 20 00 [0-16] 2d 00 70 00 61 00 74 00 68 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

