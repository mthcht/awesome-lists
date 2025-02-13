rule MonitoringTool_Win32_SpyRecon_154334_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SpyRecon"
        threat_id = "154334"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyRecon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinCbt.dll" ascii //weight: 1
        $x_1_2 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_3 = "\\WinCbt\\Release\\WinCbt.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_SpyRecon_154334_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SpyRecon"
        threat_id = "154334"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyRecon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 62 64 48 6f 6f 6b 2e 64 6c 6c 00 [0-15] 57 69 6e 43 62 74 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {77 77 77 2e 31 2d 73 70 79 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = {31 2d 53 70 79 20 4d 6f 6e 69 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {4b 65 79 6c 6f 67 67 65 72 52 65 70 6f 72 74 00 [0-15] 57 65 62 6c 6f 67 52 65 70 6f 72 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

