rule MonitoringTool_Win32_Beyond_17929_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Beyond"
        threat_id = "17929"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Beyond"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "{NUMLCK} " ascii //weight: 1
        $x_1_2 = "{CLEAR-PAD5} " ascii //weight: 1
        $x_10_3 = {40 2a 2a 2d 2a 2a 40 00}  //weight: 10, accuracy: High
        $x_2_4 = {33 c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 64}  //weight: 2, accuracy: Low
        $x_2_5 = {b3 61 b2 65 50 51 c6 45 ?? 44 c6 45 ?? 69 c6 45 ?? 73}  //weight: 2, accuracy: Low
        $x_2_6 = {b2 65 b1 72 b3 61 b0 6c 88 55}  //weight: 2, accuracy: High
        $x_2_7 = {48 c6 44 24 ?? 6b c6 44 24 ?? 45 c6 44 24 ?? 78 c6 44 24 ?? 41}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

