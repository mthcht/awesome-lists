rule Trojan_Win32_DiscoveryTechnique_ZPA_2147934408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DiscoveryTechnique.ZPA"
        threat_id = "2147934408"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DiscoveryTechnique"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "netsh" wide //weight: 1
        $x_1_2 = "wlan" wide //weight: 1
        $x_1_3 = "show profile * key=clear" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

