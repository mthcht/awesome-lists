rule MonitoringTool_Win32_AnyKeylogger_203881_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/AnyKeylogger"
        threat_id = "203881"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AnyKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "keylogger\\" wide //weight: 10
        $x_5_2 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 00}  //weight: 5, accuracy: High
        $x_1_3 = "[Enter]" wide //weight: 1
        $x_1_4 = {26 65 6d 61 69 6c 74 6f 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = "[ALT" wide //weight: 1
        $x_1_6 = "[F1" wide //weight: 1
        $x_1_7 = "{shift}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

