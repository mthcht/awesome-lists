rule MonitoringTool_Win32_GoldenEye_5794_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/GoldenEye"
        threat_id = "5794"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "GoldenEye"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 45 48 50 2e 64 6c 6c 00 49 6e 69 74 00 53 65 74 56 69 73 69 62 6c 65}  //weight: 1, accuracy: High
        $x_1_2 = {6d 43 48 53 57 44 49 4d 75 74 65 78 00}  //weight: 1, accuracy: High
        $x_1_3 = "NtCreateProcessEx" ascii //weight: 1
        $x_1_4 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

