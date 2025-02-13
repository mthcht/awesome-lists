rule MonitoringTool_Win32_SanmaxiPCManager_149499_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SanmaxiPCManager"
        threat_id = "149499"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SanmaxiPCManager"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sanmaxi PC Manager - Text Log Report" ascii //weight: 1
        $x_1_2 = "Are you sure you want to delete all captured USB/system logs permanently." ascii //weight: 1
        $x_1_3 = "Screenshot report." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_SanmaxiPCManager_149499_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SanmaxiPCManager"
        threat_id = "149499"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SanmaxiPCManager"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Sanmaxi\\KLog\\Security" wide //weight: 1
        $x_1_2 = "Sanmaxi PC Manager is still recording key strokes" ascii //weight: 1
        $x_1_3 = "http://www.key-logger.ws" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

