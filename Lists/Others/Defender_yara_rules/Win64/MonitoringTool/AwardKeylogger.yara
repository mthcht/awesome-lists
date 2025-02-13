rule MonitoringTool_Win64_AwardKeylogger_166310_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win64/AwardKeylogger"
        threat_id = "166310"
        type = "MonitoringTool"
        platform = "Win64: Windows 64-bit platform"
        family = "AwardKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 5c 6b 6c 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "/Silent /NoIcon" ascii //weight: 1
        $x_1_3 = {80 7b 10 aa 74 08 c6 04 25 00 00 00 00 78 44 8b 44 24 ?? 48 8b 54 24 ?? 48 8b cb e8 ?? ?? ?? ?? b2 20 48 8b cb e8 ?? ?? ?? ?? 80 7b 10 aa 74 08 c6 04 25 00 00 00 00 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

