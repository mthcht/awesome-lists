rule MonitoringTool_Win32_StaffCop_A_252013_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/StaffCop.A"
        threat_id = "252013"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "StaffCop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CaptureFileMonitor: [!ERROR!]" ascii //weight: 10
        $x_5_2 = "CaptureFileMonitorPort" wide //weight: 5
        $x_5_3 = "Staffcop" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

