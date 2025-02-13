rule MonitoringTool_Win32_MicroKeylogger_212596_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/MicroKeylogger"
        threat_id = "212596"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "MicroKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MicroKeylogger" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\SysLogger" wide //weight: 1
        $x_1_3 = "<screenshotfile>" wide //weight: 1
        $x_1_4 = "</keystroke>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

