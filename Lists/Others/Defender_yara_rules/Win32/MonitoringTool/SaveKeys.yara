rule MonitoringTool_Win32_SaveKeys_17974_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SaveKeys"
        threat_id = "17974"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SaveKeys"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 00 3a 00 5c 00 53 00 4b 00 35 00 31 00 5c 00 4b 00 65 00 79 00 73 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 6f 64 75 6c 65 31 00 53 4b 35 31}  //weight: 1, accuracy: High
        $x_1_3 = "SK51 was " wide //weight: 1
        $x_1_4 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

