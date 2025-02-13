rule MonitoringTool_Win32_SteelKeylogger_A_149733_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SteelKeylogger.A"
        threat_id = "149733"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SteelKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keystrokes are logged in here.." wide //weight: 1
        $x_1_2 = "hide to enter invisible mode" wide //weight: 1
        $x_1_3 = "[WindowsKey]" wide //weight: 1
        $x_1_4 = "clipboardtimer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

