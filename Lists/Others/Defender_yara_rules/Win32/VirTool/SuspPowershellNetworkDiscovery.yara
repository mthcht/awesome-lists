rule VirTool_Win32_SuspPowershellNetworkDiscovery_A_2147958103_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspPowershellNetworkDiscovery.A"
        threat_id = "2147958103"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPowershellNetworkDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = " -window hidden Get-NetIPConfiguration" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

