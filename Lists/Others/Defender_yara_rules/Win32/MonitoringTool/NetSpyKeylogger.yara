rule MonitoringTool_Win32_NetSpyKeylogger_9027_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/NetSpyKeylogger"
        threat_id = "9027"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "NetSpyKeylogger"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "211"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {53 70 79 43 6c 61 73 73 00}  //weight: 100, accuracy: High
        $x_100_2 = {52 65 6d 6f 74 65 53 70 79 00}  //weight: 100, accuracy: High
        $x_1_3 = "ZwQuerySystemInformation" ascii //weight: 1
        $x_1_4 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_5 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_6 = "IMAGEHLP.dll" ascii //weight: 1
        $x_1_7 = "GetLastTickCount" ascii //weight: 1
        $x_1_8 = "KeyHookProc" ascii //weight: 1
        $x_1_9 = {4c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_10 = "MouseHookProc" ascii //weight: 1
        $x_1_11 = {52 65 6d 6f 76 65 48 6f 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_12 = {53 65 74 48 6f 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_13 = {53 65 74 4f 70 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

