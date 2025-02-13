rule MonitoringTool_Win32_PCPandora_18032_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PCPandora"
        threat_id = "18032"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PCPandora"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pcpandora" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

