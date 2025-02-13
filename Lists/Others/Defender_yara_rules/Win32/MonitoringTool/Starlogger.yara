rule MonitoringTool_Win32_Starlogger_160911_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Starlogger"
        threat_id = "160911"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Starlogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "soft\\Windows\\CurrentVersion\\App Management\\ARPCache\\StarLogger_is1" ascii //weight: 1
        $x_1_2 = "Run StarLogger" ascii //weight: 1
        $x_1_3 = "[left windows]" ascii //weight: 1
        $x_1_4 = "Desktop will be captured regularly." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

