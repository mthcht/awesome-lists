rule MonitoringTool_Win32_SpyBuddy_11560_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SpyBuddy"
        threat_id = "11560"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyBuddy"
        severity = "8"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SpyBuddy Session Report" ascii //weight: 1
        $x_1_2 = "by SpyBuddy!" ascii //weight: 1
        $x_1_3 = "Be Monitored" ascii //weight: 1
        $x_1_4 = "keyword or phrase" ascii //weight: 1
        $x_1_5 = "_hook]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_SpyBuddy_11560_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SpyBuddy"
        threat_id = "11560"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyBuddy"
        severity = "8"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 61 6b 62 68 2e 64 6c 6c 00 43 72 65 61 74 65 00 46 72 65 65}  //weight: 1, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "%s %0.2d/%0.2d/%0.2d @ %0.2d:%0.2d:%0.2d" ascii //weight: 1
        $x_1_4 = "EAKBFileMapping" ascii //weight: 1
        $x_1_5 = "%s%dc.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_SpyBuddy_11560_2
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SpyBuddy"
        threat_id = "11560"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyBuddy"
        severity = "8"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Publisher=ExploreAnywhere Software," ascii //weight: 1
        $x_1_2 = "Title=SpyBuddy" ascii //weight: 1
        $x_1_3 = "/spybuddy-setup-" ascii //weight: 1
        $x_1_4 = "%DESKTOP%\\Downloads" ascii //weight: 1
        $x_1_5 = "SetWindowsHookExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

