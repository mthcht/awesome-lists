rule MonitoringTool_Win32_AaronKeylogger_234360_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/AaronKeylogger"
        threat_id = "234360"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AaronKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Aaron Keylogger" ascii //weight: 1
        $x_1_2 = "http://remote-keylogger.net" ascii //weight: 1
        $x_1_3 = "http://refud.me/scan.php" ascii //weight: 1
        $x_1_4 = "http://everbot.pl/cs/reg.php?id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

