rule MonitoringTool_Win32_Keylogger_168221_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Keylogger"
        threat_id = "168221"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 45 ff fe 00 eb d0 90 55 89 e5 83 ec 18 83 7d 08 01 74 08 83 7d 08 02 74 02 eb 0c c7}  //weight: 10, accuracy: High
        $x_10_2 = {83 7d 08 01 74 08 83 7d 08 02 74 02 eb 0c c7 45 f8 00 00 00 00 e9}  //weight: 10, accuracy: High
        $x_1_3 = "[SHIFT]" ascii //weight: 1
        $x_1_4 = "[CONTROL]" ascii //weight: 1
        $x_1_5 = "[BACKSPACE]" ascii //weight: 1
        $x_1_6 = {4c 4f 47 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {6c 6f 67 53 79 73 74 65 6d 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {6c 6f 67 2e 64 69 63 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Keylogger_D_228143_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Keylogger.D!bit"
        threat_id = "228143"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 54 6f 6e 67 4b 65 79 4c 6f 67 67 65 72 [0-32] 53 4d 54 50}  //weight: 1, accuracy: Low
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "Status: Mail sent success." ascii //weight: 1
        $x_1_4 = {7b 42 61 63 6b 73 70 61 63 65 7d [0-16] 7b 45 6e 74 65 72 7d [0-16] 7b 53 70 61 63 65 7d [0-16] 7b 50 72 69 6e 74 20 53 63 72 65 65 6e 7d [0-16] 7b 53 63 72 6f 6c 6c 20 4c 6f 63 6b 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

