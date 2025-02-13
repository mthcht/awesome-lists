rule MonitoringTool_Win32_Demonkey_122705_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Demonkey"
        threat_id = "122705"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Demonkey"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" wide //weight: 5
        $x_3_2 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 66 00 72 00 2e 00 62 00 61 00 74 00 00 00}  //weight: 3, accuracy: High
        $x_2_3 = "By Demon Keylogger 1.0" ascii //weight: 2
        $x_1_4 = "\\ftp.exe:*:Enabled:Microsoft" wide //weight: 1
        $x_1_5 = "cmd /c del %systemroot%\\system32\\dd.txt" wide //weight: 1
        $x_1_6 = "taskkill /f /im osk.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

