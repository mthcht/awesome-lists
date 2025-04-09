rule Trojan_Win32_PortHijack_AC_2147938349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PortHijack.AC"
        threat_id = "2147938349"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PortHijack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 00 65 00 67 00 20 00 61 00 64 00 64 00 [0-4] 68 00 6b 00 65 00 79 00 5f 00 6c 00 6f 00 63 00 61 00 6c 00 5f 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 5c 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 73 00 65 00 74 00 5c 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 70 00 72 00 69 00 6e 00 74 00 5c 00 6d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 73 00 5c 00 61 00 74 00 74 00 61 00 63 00 6b 00 69 00 71 00 [0-10] 64 00 72 00 69 00 76 00 65 00 72 00 [0-48] 2e 00 64 00 6c 00 6c 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

