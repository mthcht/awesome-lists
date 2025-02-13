rule Trojan_Win32_Colorexe_B_2147850163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Colorexe.B"
        threat_id = "2147850163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Colorexe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $n_11_1 = {37 00 7a 00 2e 00 65 00 78 00 65 00 [0-4] 61 00 20 00 2d 00 74 00 7a 00 69 00 70 00 20 00 2d 00 6d 00 6d 00 74 00 20 00 2d 00 61 00 6f 00 75 00 20 00 2d 00 73 00 73 00 77 00}  //weight: -11, accuracy: Low
        $x_10_2 = {5c 00 73 00 70 00 6f 00 6f 00 6c 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 63 00 6f 00 6c 00 6f 00 72 00 5c 00 [0-255] 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_3 = {5c 00 73 00 70 00 6f 00 6f 00 6c 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 63 00 6f 00 6c 00 6f 00 72 00 5c 00 [0-255] 2e 00 64 00 6c 00 6c 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

