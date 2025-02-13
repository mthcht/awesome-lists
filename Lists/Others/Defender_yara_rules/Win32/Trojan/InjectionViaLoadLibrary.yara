rule Trojan_Win32_InjectionViaLoadLibrary_A_2147927125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/InjectionViaLoadLibrary.A"
        threat_id = "2147927125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "InjectionViaLoadLibrary"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5c 00 69 00 6e 00 6a 00 65 00 63 00 74 00 6f 00 72 00 5f 00 31 00 5f 00 78 00 36 00 34 00 2e 00 65 00 78 00 65 00 20 00 73 00 6c 00 65 00 65 00 70 00 69 00 6e 00 67 00 5f 00 62 00 69 00 6e 00 61 00 72 00 79 00 5f 00 78 00 36 00 34 00 2e 00 65 00 78 00 65 00 [0-176] 5c 00 69 00 6e 00 6a 00 65 00 63 00 74 00 61 00 62 00 6c 00 65 00 5f 00 64 00 6c 00 6c 00 5f 00 78 00 36 00 34 00 2e 00 64 00 6c 00 6c 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

