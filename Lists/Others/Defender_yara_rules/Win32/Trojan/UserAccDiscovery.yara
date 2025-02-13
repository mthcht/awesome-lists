rule Trojan_Win32_UserAccDiscovery_A_2147918746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UserAccDiscovery.A"
        threat_id = "2147918746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UserAccDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net localgroup" wide //weight: 1
        $x_1_2 = "net.exe user" wide //weight: 1
        $x_1_3 = "net.exe group \"domain admins\" /domain" wide //weight: 1
        $x_1_4 = "net.exe group \"exchange trusted subsystem\" /domain" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

