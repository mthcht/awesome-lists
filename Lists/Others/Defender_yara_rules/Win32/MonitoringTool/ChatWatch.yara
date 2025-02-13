rule MonitoringTool_Win32_ChatWatch_14847_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/ChatWatch"
        threat_id = "14847"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ChatWatch"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Yahoo Logs" wide //weight: 2
        $x_3_2 = "ChatWatch4.TrayIcon" ascii //weight: 3
        $x_2_3 = "The chat logs are attached to this e-mail message." wide //weight: 2
        $x_3_4 = "cw4_log\\cwlogs.ini" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

