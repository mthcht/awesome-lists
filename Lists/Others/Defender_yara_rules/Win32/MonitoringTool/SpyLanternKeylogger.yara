rule MonitoringTool_Win32_SpyLanternKeylogger_17955_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SpyLanternKeylogger"
        threat_id = "17955"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyLanternKeylogger"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Log Files (*.ltr)" ascii //weight: 2
        $x_2_2 = "is_localspy" wide //weight: 2
        $x_2_3 = "Spydex, Inc." ascii //weight: 2
        $x_2_4 = "report_key_bottom.templ" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_SpyLanternKeylogger_17955_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SpyLanternKeylogger"
        threat_id = "17955"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyLanternKeylogger"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 6b 33 34 35 33 34 32 33 34 4d 45 44 52 45 57 73 64 66 77 65 4c 61 75 6e 63 68 4d 75 74 65 78 00}  //weight: 1, accuracy: High
        $x_1_2 = "gateway.messenger.hotmail.com" ascii //weight: 1
        $x_1_3 = "rk_ctrl_noidle32" ascii //weight: 1
        $x_1_4 = "__ITSNOTROOM__" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_SpyLanternKeylogger_17955_2
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SpyLanternKeylogger"
        threat_id = "17955"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyLanternKeylogger"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 73 5c 50 49 50 45 5c 25 73 5f 63 74 72 6c 00 [0-16] 5c 5c 25 73 5c 50 49 50 45 5c 25 73 5f 64 61 74 61 25 75 00}  //weight: 1, accuracy: Low
        $x_1_2 = {53 70 79 20 4c 61 6e 74 65 72 6e 20 4b 65 79 6c 6f 67 67 65 72 00 [0-16] 25 73 5f 68 6b 6d 61 70 00 [0-16] 25 73 5c 64 62 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {53 70 79 20 4c 61 6e 74 65 72 6e 20 4b 65 79 6c 6f 67 67 65 72 5c [0-53] 3c 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 3e [0-32] 3c 55 6e 69 71 49 44 20 6e 61 6d 65 3d 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

