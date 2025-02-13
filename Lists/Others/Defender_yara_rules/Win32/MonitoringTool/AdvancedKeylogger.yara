rule MonitoringTool_Win32_AdvancedKeylogger_17071_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/AdvancedKeylogger"
        threat_id = "17071"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AdvancedKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "A2C2EF5F-E200-417e-AE20-B1B241E6BE39" ascii //weight: 1
        $x_1_2 = "AreyouSureDeleteThisLog" ascii //weight: 1
        $x_1_3 = "ScreentshotPageCol" ascii //weight: 1
        $x_1_4 = ".com/xpadvancedkeylogger/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule MonitoringTool_Win32_AdvancedKeylogger_17071_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/AdvancedKeylogger"
        threat_id = "17071"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AdvancedKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_7_1 = "Advanced Keylogger is watching you" ascii //weight: 7
        $x_7_2 = "Preparing to send log via email..." ascii //weight: 7
        $x_8_3 = "PRODUCED BY ADVANCED KEYLOGGER LOG PARSER" ascii //weight: 8
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

