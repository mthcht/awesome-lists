rule MonitoringTool_Win32_HandyKeylogger_17510_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/HandyKeylogger"
        threat_id = "17510"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "HandyKeylogger"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PRODUCED BY HANDY KEYLOGGER LOG PARSER" ascii //weight: 1
        $x_1_2 = "WideStep Software." ascii //weight: 1
        $x_1_3 = "Handy Keylogger:" ascii //weight: 1
        $x_1_4 = "Keylogger's threads shut down successfully." ascii //weight: 1
        $x_1_5 = "RECENT KEY LOG" ascii //weight: 1
        $x_1_6 = "SPYKEYHOOK" ascii //weight: 1
        $x_1_7 = "HW_KEYBOARD hook installation successful." ascii //weight: 1
        $x_1_8 = "HW_GETMESSAGE hook installation error." ascii //weight: 1
        $x_1_9 = "SpySysLog:" ascii //weight: 1
        $x_1_10 = "support@widestep.com" ascii //weight: 1
        $x_1_11 = "one instance of the Handy Keylogger can be launched" ascii //weight: 1
        $x_1_12 = "Handy Keylogger registration..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

