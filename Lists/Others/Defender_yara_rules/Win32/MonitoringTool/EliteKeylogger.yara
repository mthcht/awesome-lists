rule MonitoringTool_Win32_EliteKeylogger_17187_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/EliteKeylogger"
        threat_id = "17187"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "EliteKeylogger"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Invisible mode" ascii //weight: 1
        $x_1_2 = "Software\\WideStep\\EliteKeylogger" ascii //weight: 1
        $x_1_3 = {57 69 64 65 53 74 65 70 20 45 6c 69 74 65 20 4b 65 79 6c 6f 67 67 65 72 [0-16] 5b 62 75 69 6c 64 [0-16] 5d [0-2] 53 65 74 75 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

