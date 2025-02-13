rule Trojan_Win32_PriteAdminUser_A_2147784040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PriteAdminUser.A"
        threat_id = "2147784040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PriteAdminUser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "net localgroup" wide //weight: 2
        $x_1_2 = "/add" wide //weight: 1
        $x_1_3 = "administrators" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

