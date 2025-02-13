rule MonitoringTool_Win32_007Spy_17530_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/007Spy"
        threat_id = "17530"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "007Spy"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.e-spy-software.com" ascii //weight: 1
        $x_1_2 = "www.e-spy-software.com" wide //weight: 1
        $x_10_3 = "Timer_KillAdaware" ascii //weight: 10
        $x_10_4 = "Check this to make 007 Spy" ascii //weight: 10
        $x_10_5 = "Timer_Keylogger" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_007Spy_17530_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/007Spy"
        threat_id = "17530"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "007Spy"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {44 00 3a 00 5c 00 44 00 65 00 76 00 65 00 6c 00 6f 00 70 00 5c 00 6d 00 79 [0-2] 00 77 00 6f 00 72 00 6b [0-5] 5c 00 30 00 30 00 37 00 53 00 70 00 79 00 33}  //weight: 10, accuracy: Low
        $x_1_2 = "Monitoring engine" ascii //weight: 1
        $x_1_3 = "Timer_Keylogger" ascii //weight: 1
        $x_1_4 = "Spy007.MyXPButton" ascii //weight: 1
        $x_1_5 = {66 72 6d 4d 61 69 6e 00 0d 01 10 00 30 30 37 20 53 70 79 20 53 6f 66 74 77 61 72 65}  //weight: 1, accuracy: High
        $x_1_6 = "keybd_log321_KeyPressed" ascii //weight: 1
        $x_1_7 = "www.e-spy-software.com" wide //weight: 1
        $x_1_8 = {73 76 63 68 6f 73 74 00 73 76 63 68 6f 73 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

