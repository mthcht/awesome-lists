rule MonitoringTool_Win32_KeyloggerW_A_177864_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/KeyloggerW.A"
        threat_id = "177864"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyloggerW"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\tasks\\index.dat" ascii //weight: 1
        $x_1_2 = "Ttle: %s" ascii //weight: 1
        $x_1_3 = "\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "Wscntfy" ascii //weight: 1
        $x_1_5 = "[Right]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

