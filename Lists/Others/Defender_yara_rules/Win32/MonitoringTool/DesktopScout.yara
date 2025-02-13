rule MonitoringTool_Win32_DesktopScout_196640_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/DesktopScout"
        threat_id = "196640"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DesktopScout"
        severity = "23"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 74 73 70 72 6f 63 2e 64 6c 6c 00 6a 00 a1 50}  //weight: 1, accuracy: High
        $x_1_2 = {73 76 63 61 67 6e 74 2e 65 78 65 00 55 8b ec 81}  //weight: 1, accuracy: High
        $x_1_3 = {70 72 6f 63 65 78 70 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 74 61 72 74 53 74 65 61 6c 74 68 48 6f 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 74 6f 70 53 74 65 61 6c 74 68 48 6f 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_6 = "[Backspace]" wide //weight: 1
        $x_1_7 = "[Esc]" wide //weight: 1
        $x_1_8 = "[Tab]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_DesktopScout_196640_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/DesktopScout"
        threat_id = "196640"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DesktopScout"
        severity = "23"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Uninstall\\Desktop Scout" ascii //weight: 1
        $x_1_2 = "chkScreenLoggerEnabledClick" ascii //weight: 1
        $x_1_3 = "dtsbrand.dat" ascii //weight: 1
        $x_1_4 = "Global\\DTS3Mutex30STP" ascii //weight: 1
        $x_1_5 = "\\system32\\config\\systemprofile\\" ascii //weight: 1
        $x_1_6 = "TScreenLogger.Created" wide //weight: 1
        $x_1_7 = "TUrlLogger.Created" wide //weight: 1
        $x_1_8 = "TDiskLogger.Created" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_DesktopScout_196640_2
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/DesktopScout"
        threat_id = "196640"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DesktopScout"
        severity = "23"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Desktop Scout." wide //weight: 1
        $x_1_2 = "ip.globalpatrol.net/" wide //weight: 1
        $x_1_3 = "IPFetchUsername" wide //weight: 1
        $x_1_4 = "[Backspace]" wide //weight: 1
        $x_1_5 = "Send Ctrl-Alt-Del" wide //weight: 1
        $x_1_6 = "[Licensed to monitor %d Agents]" wide //weight: 1
        $x_1_7 = "Confirm Agent Shutdown" wide //weight: 1
        $x_1_8 = "Process Manager" wide //weight: 1
        $x_1_9 = "modapp\\" wide //weight: 1
        $x_1_10 = "modscr\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

