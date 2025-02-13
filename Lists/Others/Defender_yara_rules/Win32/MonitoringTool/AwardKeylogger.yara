rule MonitoringTool_Win32_AwardKeylogger_166309_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/AwardKeylogger"
        threat_id = "166309"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AwardKeylogger"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "DisableAntiSpyApp" ascii //weight: 5
        $x_5_2 = "stealth" ascii //weight: 5
        $x_1_3 = "smtp server" ascii //weight: 1
        $x_1_4 = "/Silent /NoIcon" ascii //weight: 1
        $x_1_5 = "Keylogger" wide //weight: 1
        $x_1_6 = "Monitoring engine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

