rule Trojan_Win32_WMIPersistance_A_2147919726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WMIPersistance.A"
        threat_id = "2147919726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WMIPersistance"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 77 00 62 00 65 00 6d 00 5c 00 6d 00 6f 00 66 00 63 00 6f 00 6d 00 70 00 2e 00 65 00 78 00 65 00 [0-9] 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 [0-32] 2e 00 6d 00 6f 00 66 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WMIPersistance_B_2147957291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WMIPersistance.B"
        threat_id = "2147957291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WMIPersistance"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mofcomp.exe" wide //weight: 1
        $x_1_2 = "\\temp\\ai-" wide //weight: 1
        $x_1_3 = ".mof" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

