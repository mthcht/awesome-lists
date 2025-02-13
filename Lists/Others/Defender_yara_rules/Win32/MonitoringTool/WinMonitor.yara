rule MonitoringTool_Win32_WinMonitor_223020_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/WinMonitor"
        threat_id = "223020"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "WinMonitor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AntSpy" ascii //weight: 1
        $x_1_2 = "fRECWCam" ascii //weight: 1
        $x_1_3 = "TS Security\\" wide //weight: 1
        $x_1_4 = "d_HideSystemFiles" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

