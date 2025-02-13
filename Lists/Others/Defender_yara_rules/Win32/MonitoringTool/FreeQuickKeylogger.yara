rule MonitoringTool_Win32_FreeQuickKeylogger_150663_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/FreeQuickKeylogger"
        threat_id = "150663"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "FreeQuickKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WideStep Free License Agreement" ascii //weight: 1
        $x_1_2 = "Free Quick Keylogger" ascii //weight: 1
        $x_1_3 = {71 75 69 63 6b 5f 65 6e 67 69 6e 65 2e 65 78 65 00 71 6b 5f 75 73 65 72 5f 67 75 69 64 65 2e 68 74 6d 00 51 75 69 63 6b 41 70 70 49 6e 69 74 2e 64 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_FreeQuickKeylogger_150663_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/FreeQuickKeylogger"
        threat_id = "150663"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "FreeQuickKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Free Quick Keylogger Log.htm" ascii //weight: 1
        $x_1_2 = "widestep.com" ascii //weight: 1
        $x_1_3 = "Free Quick Keylogger is already running." ascii //weight: 1
        $x_1_4 = "Thank you for choosing Free Quick Keylogger" ascii //weight: 1
        $x_1_5 = "HW_KEYBOARD hook installation successful." ascii //weight: 1
        $x_1_6 = "HW_GETMESSAGE hook uninstallation successful." ascii //weight: 1
        $x_1_7 = "quick_engine.exe" ascii //weight: 1
        $x_1_8 = "quicklogs.bin" ascii //weight: 1
        $x_1_9 = "quick.jrn" ascii //weight: 1
        $x_1_10 = "one instance of the Free Quick Keylogger can be launched" ascii //weight: 1
        $x_1_11 = "while switching to invisible mode." ascii //weight: 1
        $x_1_12 = "SPYKEYHOOK" ascii //weight: 1
        $x_1_13 = "{setup keyboard hooks}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

