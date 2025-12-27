rule VirTool_Win32_SuspProcessTermination_A_2147956365_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspProcessTermination.A"
        threat_id = "2147956365"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProcessTermination"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = " -c " wide //weight: 1
        $x_1_3 = "get-process iexplore" wide //weight: 1
        $x_1_4 = "select -expand id;" wide //weight: 1
        $x_1_5 = "Stop-Process -Id $" wide //weight: 1
        $x_1_6 = " -Force" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

