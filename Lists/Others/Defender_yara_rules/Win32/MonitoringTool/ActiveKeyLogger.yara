rule MonitoringTool_Win32_ActiveKeyLogger_1622_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/ActiveKeyLogger"
        threat_id = "1622"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ActiveKeyLogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Advanced Invisible Keylogger (Keystrokes Typed)" ascii //weight: 1
        $x_1_2 = {54 69 6d 65 3a [0-16] 57 69 6e 64 6f 77 20 54 69 74 6c 65 3a [0-16] 4b 65 79 73 74 72 6f 6b 65 73 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_ActiveKeyLogger_1622_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/ActiveKeyLogger"
        threat_id = "1622"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ActiveKeyLogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 53 4f 46 54 57 41 52 45 5c 57 69 6e 73 6f 75 6c 5c [0-2] 4b 65 79 6c 6f 67 67 65 72}  //weight: 10, accuracy: Low
        $x_2_2 = {2e 64 6c 6c 00 53 65 74 48 6f 6f 6b 00}  //weight: 2, accuracy: High
        $x_2_3 = {41 63 74 69 76 65 20 4b 65 79 20 4c 6f 67 67 65 72 20 52 65 70 6f 72 74 [0-20] 2e 61 64 64 72 65 73 73 2e 63 6f 6d}  //weight: 2, accuracy: Low
        $x_2_4 = {54 6f 74 61 6c 57 69 6e [0-16] 41 63 74 69 76 65 20 4b 65 79 20 4c 6f 67 67 65 72 3a 20 4b 65 79 73 74 72 6f 6b 65 73}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

