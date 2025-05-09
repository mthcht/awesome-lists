rule Trojan_Win32_Cwordol_A_2147941045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cwordol.A"
        threat_id = "2147941045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cwordol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 00 74 00 78 00 74 00 26 00 63 00 75 00 72 00 6c 00 20 00 25 00 [0-8] 25 00 25 00 [0-8] 25 00 25 00 [0-8] 25 00 25 00 [0-8] 25 00}  //weight: 1, accuracy: Low
        $x_1_2 = {20 00 2d 00 6f 00 20 00 25 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 25 00 5c 00 [0-16] 2e 00 6d 00 73 00 63 00 20 00 [0-32] 20 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 [0-10] 25 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 [0-16] 2e 00 6d 00 73 00 63 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

