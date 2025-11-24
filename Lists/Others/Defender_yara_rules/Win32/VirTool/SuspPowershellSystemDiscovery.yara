rule VirTool_Win32_SuspPowershellSystemDiscovery_A_2147958105_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspPowershellSystemDiscovery.A"
        threat_id = "2147958105"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPowershellSystemDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = " /c " wide //weight: 1
        $x_1_3 = "powershell.exe " wide //weight: 1
        $x_1_4 = " Get-WmiObject -Class win32_ComputerSystemn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

