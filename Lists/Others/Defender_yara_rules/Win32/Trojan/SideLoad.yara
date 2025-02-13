rule Trojan_Win32_SideLoad_M_2147836668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SideLoad.M!MSR"
        threat_id = "2147836668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SideLoad"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cef_shutdown" ascii //weight: 1
        $x_1_2 = "cef_post_task" ascii //weight: 1
        $x_1_3 = "CCmdTarget" ascii //weight: 1
        $x_1_4 = "Enpud.png" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "MonitorFromWindow" ascii //weight: 1
        $x_1_7 = "MonitorFromRect" ascii //weight: 1
        $x_1_8 = "MonitorFromPoint" ascii //weight: 1
        $x_1_9 = "EnumDisplayMonitors" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

