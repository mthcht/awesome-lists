rule MonitoringTool_Win32_Sfkeylogger_153036_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Sfkeylogger"
        threat_id = "153036"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Sfkeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PAGE DOWN" ascii //weight: 1
        $x_2_2 = "c:\\klg-err.log" ascii //weight: 2
        $x_2_3 = "sfklgcp.exe" ascii //weight: 2
        $x_1_4 = "Unable to open the %s (log)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

