rule MonitoringTool_Win32_FreeKeylogger_17558_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/FreeKeylogger"
        threat_id = "17558"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "FreeKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&Show Free Key Logger" ascii //weight: 1
        $x_1_2 = "Monitoring Resumed" ascii //weight: 1
        $x_1_3 = "TClipboardMonitorS" ascii //weight: 1
        $x_1_4 = "Do you want to clear logs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

