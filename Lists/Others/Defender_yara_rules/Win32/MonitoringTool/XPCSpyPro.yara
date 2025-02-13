rule MonitoringTool_Win32_XPCSpyPro_12155_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/XPCSpyPro"
        threat_id = "12155"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "XPCSpyPro"
        severity = "13"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XPCSpyPro\\IESpy" ascii //weight: 1
        $x_1_2 = "XPCSpyPro_WebMail" ascii //weight: 1
        $x_1_3 = {49 4d 6f 6e 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

