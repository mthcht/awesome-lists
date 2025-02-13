rule Trojan_Win32_PhantomShell_C_2147851417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PhantomShell.C"
        threat_id = "2147851417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PhantomShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "csc.exe" wide //weight: 1
        $x_10_2 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-255] 2e 00 63 00 6d 00 64 00 6c 00 69 00 6e 00 65 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

