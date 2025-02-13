rule MonitoringTool_Win32_HomeKeylogger_6175_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/HomeKeylogger"
        threat_id = "6175"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "HomeKeylogger"
        severity = "6"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HOMEKEYLOGGER_MUTEX" ascii //weight: 2
        $x_2_2 = "CKMiNT21HOMEKEYLOGGER" ascii //weight: 2
        $x_1_3 = "I can't set Keyboard Hook!" ascii //weight: 1
        $x_1_4 = "I can create main window!" ascii //weight: 1
        $x_1_5 = "InstallKeyboardHook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

