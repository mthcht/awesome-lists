rule MonitoringTool_Win32_GhostXP_155877_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/GhostXP"
        threat_id = "155877"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostXP"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 68 6f 73 74 58 50 00 [0-16] 53 4f 46 54 57 41 52 45 5c 4d 49 43 52 4f 53 4f 46 54 [0-16] 52 65 63 79 63 6c 65 72 [0-16] 5c 77 33 77 69 6e 78 70 2e 69 6e 69 [0-16] 5c 77 34 77 69 6e 2e 69 6e 69}  //weight: 1, accuracy: Low
        $x_1_2 = {44 61 74 61 44 65 49 6e 73 74 00 [0-16] 44 61 74 61 48 69 73 74 52 6f 7a 00 [0-16] 44 61 74 61 48 69 73 74 5a 61 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

