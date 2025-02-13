rule MonitoringTool_Win32_SpyKeylogger_14863_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SpyKeylogger"
        threat_id = "14863"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyKeylogger"
        severity = "14"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6b 6c 2e 64 6c 6c [0-4] 6b 6c 49 6e 69 74 69 61 6c 69 7a 65 64}  //weight: 10, accuracy: Low
        $x_10_2 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 10
        $x_1_3 = "Key logger dinamic link library" wide //weight: 1
        $x_1_4 = "KeyLoggerMessage" wide //weight: 1
        $x_1_5 = "KeyLoggerSharedMem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

