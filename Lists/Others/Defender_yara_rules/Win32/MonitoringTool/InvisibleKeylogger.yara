rule MonitoringTool_Win32_InvisibleKeylogger_7197_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/InvisibleKeylogger"
        threat_id = "7197"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "InvisibleKeylogger"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " Invisible Keylogger" ascii //weight: 1
        $x_1_2 = "keystrokes typed" ascii //weight: 1
        $x_1_3 = "DisableAntispy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

