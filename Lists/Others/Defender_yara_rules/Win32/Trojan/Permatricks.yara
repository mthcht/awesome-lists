rule Trojan_Win32_Permatricks_B_2147766608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Permatricks.B"
        threat_id = "2147766608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Permatricks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "create " wide //weight: 1
        $x_1_2 = {62 00 69 00 6e 00 70 00 61 00 74 00 68 00 [0-2] 3d 00 [0-64] 72 00 77 00 64 00 72 00 76 00 2e 00 73 00 79 00 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {74 00 79 00 70 00 65 00 [0-2] 3d 00 [0-16] 6b 00 65 00 72 00 6e 00 65 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

