rule Trojan_Win32_Boriles_A_2147705617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Boriles.A"
        threat_id = "2147705617"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Boriles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "R0JQTFVHSU4=" wide //weight: 1
        $x_1_2 = "XFdpbmRvd3MgRGVmZW5kZXI=" wide //weight: 1
        $x_1_3 = "SW5mb3JtYT8/ZXMgZGUgU2VndXJhbj9h" wide //weight: 1
        $x_1_4 = "U3VuQXd0RGlhbG9n" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

