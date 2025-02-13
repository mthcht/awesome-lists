rule MonitoringTool_Win32_PCAgent_9606_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PCAgent"
        threat_id = "9606"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PCAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LogonPwWatch" ascii //weight: 1
        $x_1_2 = "PCA_SETTINGS" ascii //weight: 1
        $x_1_3 = "HookWatch.GetMouseMessage" ascii //weight: 1
        $x_1_4 = " PCA Mailer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_PCAgent_9606_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PCAgent"
        threat_id = "9606"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PCAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PC Monitoring Software" ascii //weight: 1
        $x_1_2 = "blue-series.de" ascii //weight: 1
        $x_1_3 = "Open and view the log-files" ascii //weight: 1
        $x_1_4 = "PcaCheckVersionChkVAvailable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

