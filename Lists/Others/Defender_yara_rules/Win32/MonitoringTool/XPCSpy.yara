rule MonitoringTool_Win32_XPCSpy_14821_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/XPCSpy"
        threat_id = "14821"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "XPCSpy"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XPCSpy Pro Application Mutex" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_3 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellPath" ascii //weight: 1
        $x_1_4 = {73 79 73 74 65 6d 69 6e 2e 73 79 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

