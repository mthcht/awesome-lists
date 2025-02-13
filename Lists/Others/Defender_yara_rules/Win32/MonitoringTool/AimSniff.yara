rule MonitoringTool_Win32_AimSniff_156012_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/AimSniff"
        threat_id = "156012"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AimSniff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 64 00 70 00 6e 00 73 00 76 00 72 00 61 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {00 00 5c 00 61 00 69 00 6d 00 61 00 70 00 70 00 69 00 6e 00 69 00 2e 00 69 00 6e 00 69 00}  //weight: 2, accuracy: High
        $x_1_3 = {61 64 73 6e 77 61 00 73 76 63 68 6f 73 74}  //weight: 1, accuracy: High
        $x_1_4 = {00 5c 00 64 00 61 00 74 00 61 00 5c 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {00 00 5c 00 65 00 6d 00 78 00 66 00 69 00 6c 00 65 00 30 00 30 00 34 00 2e 00 64 00 61 00 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

