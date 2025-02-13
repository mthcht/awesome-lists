rule Trojan_Win32_NetworkDiscovery_B_2147766427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetworkDiscovery.B!pwsh"
        threat_id = "2147766427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetworkDiscovery"
        severity = "Critical"
        info = "pwsh: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get-nettcpconnection" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

