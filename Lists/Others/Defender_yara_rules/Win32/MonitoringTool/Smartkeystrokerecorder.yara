rule MonitoringTool_Win32_Smartkeystrokerecorder_17577_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Smartkeystrokerecorder"
        threat_id = "17577"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Smartkeystrokerecorder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 6d 61 72 74 20 4b 65 79 73 74 72 6f 6b 65 20 52 65 63 6f 72 64 65 72 00}  //weight: 2, accuracy: High
        $x_2_2 = {00 00 63 3a 5c 50 72 6f 6a 65 63 74 73 5c 53 6d 61 72 74 4b 65 79 73 74 72 6f 6b 65 52 65 63 6f 72 64 65 72}  //weight: 2, accuracy: High
        $x_2_3 = "SmartMonitorAgent_WindowClass_" ascii //weight: 2
        $x_2_4 = {00 53 6d 61 72 74 4d 6f 6e 69 74 6f 72 41 67 65 6e 74 5f 76 31 5f 30 00}  //weight: 2, accuracy: High
        $x_1_5 = {00 53 6d 61 72 74 4b 65 79 73 74 72 6f 6b 65 52 65 63 6f 72 64 65 72 2e 63 68 6d 3a 3a 2f 68 74 6d 6c 2f 00}  //weight: 1, accuracy: High
        $x_1_6 = {6f 70 65 6e 00 00 00 00 73 6b 72 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_7 = "Are you sure you want to delete screenshots?" ascii //weight: 1
        $x_1_8 = "smartkeystrokerecorder.com/order.htm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

