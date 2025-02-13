rule MonitoringTool_Win32_BRMonitor_165691_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/BRMonitor"
        threat_id = "165691"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "BRMonitor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Relatorio.htm" ascii //weight: 1
        $x_1_2 = "MSNMonSnifferMessage" ascii //weight: 1
        $x_1_3 = {be 01 00 00 00 33 c0 8a 84 35 ?? ?? ff ff 33 c3 89 45 f0 3b 7d f0 7c 0f 8b 45 f0 05 ff 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

