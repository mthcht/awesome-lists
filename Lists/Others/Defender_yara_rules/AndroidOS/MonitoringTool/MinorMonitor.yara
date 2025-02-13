rule MonitoringTool_AndroidOS_MinorMonitor_A_348263_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MinorMonitor.A!MTB"
        threat_id = "348263"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MinorMonitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1a 00 00 00 1a 01 ?? 00 6e 30 ?? ?? 15 00 0c 05 1a 02 ?? ?? 13 03 2e 00 13 04 20 00 6e 30 ?? ?? 32 04 0c 02 12 43 6e 20 ?? ?? 32 00 0c 02 6e 30 ?? ?? 12 00 0c 00 6e 10 ?? ?? 00 00 0c 00 6e 10 ?? ?? 05 00 0c 05 12 01 71 20 ?? ?? 15 00 0c 05 71 20 ?? ?? 05 00 22 00 ?? ?? 70 20 ?? ?? 50 00 11 00}  //weight: 1, accuracy: Low
        $x_1_2 = {1a 00 00 00 6e 10 ?? ?? 00 00 0a 01 13 02 10 00 35 21 12 00 22 01 ?? ?? 70 10 ?? ?? 01 00 6e 20 ?? ?? 01 00 6e 20 ?? ?? 31 00 6e 10 ?? ?? 01 00 0c 00 28 e9 12 01 6e 30 ?? ?? 10 02 0c 00 1a 01 ?? ?? 6e 20 ?? ?? 10 00 0c 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

