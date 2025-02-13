rule MonitoringTool_Win32_MiniKeyLog_8510_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/MiniKeyLog"
        threat_id = "8510"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "MiniKeyLog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Simple keylogger <" ascii //weight: 10
        $x_10_2 = {8b c3 0d 00 00 00 40 3b d8 75 6a 68 ?? ?? 40 00 6a 00 e8 ?? ff ff ff 89 45 fc 68 ?? ?? 40 00 e8 ?? ff ff ff}  //weight: 10, accuracy: Low
        $x_1_3 = "GetKeyboardState" ascii //weight: 1
        $x_1_4 = "SetKeyHook" ascii //weight: 1
        $x_1_5 = "SetWindowsHookExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_MiniKeyLog_8510_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/MiniKeyLog"
        threat_id = "8510"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "MiniKeyLog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mini Key Log - PC Monitoring Software" wide //weight: 1
        $x_1_2 = "http://www.blue-series.de" wide //weight: 1
        $x_1_3 = "MiniKeyLog" wide //weight: 1
        $x_1_4 = "publicKeyToken=\"6595b64144ccf1df\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

