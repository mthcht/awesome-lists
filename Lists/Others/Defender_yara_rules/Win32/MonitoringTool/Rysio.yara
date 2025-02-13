rule MonitoringTool_Win32_Rysio_132912_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Rysio"
        threat_id = "132912"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Rysio"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "RysioLogger " ascii //weight: 10
        $x_10_2 = "DisableTaskMgr" ascii //weight: 10
        $x_5_3 = {5c 70 6c 69 6b 2e 65 78 65 00}  //weight: 5, accuracy: High
        $x_5_4 = {00 41 6e 74 79 56 69 72 75 73 00}  //weight: 5, accuracy: High
        $x_2_5 = {68 61 73 6c 6f 00}  //weight: 2, accuracy: High
        $x_2_6 = "klijent" ascii //weight: 2
        $x_1_7 = "keylogger" ascii //weight: 1
        $x_1_8 = "KeySpy" ascii //weight: 1
        $x_1_9 = "onmobilelog" ascii //weight: 1
        $x_1_10 = "showclockt" ascii //weight: 1
        $x_1_11 = "onbrowserh" ascii //weight: 1
        $x_1_12 = "ScreenShot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

