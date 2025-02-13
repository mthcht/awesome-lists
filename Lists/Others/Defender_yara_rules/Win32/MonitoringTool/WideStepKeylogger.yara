rule MonitoringTool_Win32_WideStepKeylogger_150664_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/WideStepKeylogger"
        threat_id = "150664"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "WideStepKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QuickKeyloggerClass" ascii //weight: 1
        $x_1_2 = "Now, please, launch the Keylogger for the first time." ascii //weight: 1
        $x_1_3 = "@Keylogger installation complete." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

