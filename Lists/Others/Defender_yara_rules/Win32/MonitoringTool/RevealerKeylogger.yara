rule MonitoringTool_Win32_RevealerKeylogger_122375_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/RevealerKeylogger"
        threat_id = "122375"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RevealerKeylogger"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Revealer Keylogger Pro" wide //weight: 1
        $x_1_2 = "_LowLevelKeyboardProc@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_RevealerKeylogger_122375_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/RevealerKeylogger"
        threat_id = "122375"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RevealerKeylogger"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 77 00 77 00 77 00 2e 00 72 00 65 00 76 00 65 00 61 00 6c 00 65 00 72 00 6b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 00 00 ?? 00 18 00 01 00 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 52 00 65 00 76 00 65 00 61 00 6c 00 65 00 72 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00}  //weight: 5, accuracy: Low
        $x_3_2 = {00 52 00 65 00 76 00 65 00 61 00 6c 00 65 00 72 00 20 00 69 00 73 00 20 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 6c 00 79 00 20 00 6d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 2c 00 20 00 61 00 72 00 65 00 20 00 79 00 6f 00 75 00 20 00 73 00 75 00 72 00 65 00 20 00 79 00 6f 00 75 00 20 00 77 00 61 00 6e 00 74 00 20 00 74 00 6f 00 20 00 71 00 75 00 69 00 74 00}  //weight: 3, accuracy: High
        $x_2_3 = {00 77 00 77 00 77 00 2e 00 72 00 65 00 76 00 65 00 61 00 6c 00 65 00 72 00 6b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 63 00 6f 00 6d 00}  //weight: 2, accuracy: High
        $x_2_4 = {01 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 52 00 65 00 76 00 65 00 61 00 6c 00 65 00 72 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00}  //weight: 2, accuracy: High
        $x_2_5 = {00 52 00 65 00 76 00 65 00 61 00 6c 00 65 00 72 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 72 00 65 00 70 00 6f 00 72 00 74 00}  //weight: 2, accuracy: High
        $x_1_6 = "rkfree.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

