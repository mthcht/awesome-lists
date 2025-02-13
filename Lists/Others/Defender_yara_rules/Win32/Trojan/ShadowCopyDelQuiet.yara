rule Trojan_Win32_ShadowCopyDelQuiet_A_2147785319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShadowCopyDelQuiet.A"
        threat_id = "2147785319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadowCopyDelQuiet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "150"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 64 00 65 00 6c 00 65 00 74 00 65 00 [0-16] 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00}  //weight: 100, accuracy: Low
        $x_25_2 = " /all" wide //weight: 25
        $x_25_3 = " /quiet" wide //weight: 25
        $x_1_4 = "f4e67c81-9d15-415f-8c29-b30b4bfea692" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_25_*))) or
            (all of ($x*))
        )
}

