rule VirTool_Win32_SuspNetworkDiscovery_A_2147958110_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspNetworkDiscovery.A"
        threat_id = "2147958110"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspNetworkDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_1_2 = " /c " wide //weight: 1
        $x_1_3 = "netstat -a" wide //weight: 1
        $x_1_4 = "findstr LISTENING" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

