rule MonitoringTool_Win32_SpyAgent_11555_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SpyAgent"
        threat_id = "11555"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyAgent"
        severity = "13"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\windows\\lsass.exe" ascii //weight: 2
        $x_2_2 = "SPYAGENT@" ascii //weight: 2
        $x_1_3 = "=>Keylogger Start" ascii //weight: 1
        $x_1_4 = "Victim is Online" ascii //weight: 1
        $x_1_5 = " URL HISTORY =" ascii //weight: 1
        $x_1_6 = "Log Start  " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_SpyAgent_11555_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SpyAgent"
        threat_id = "11555"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyAgent"
        severity = "13"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SpyAgent_HWND32" ascii //weight: 1
        $x_1_2 = "%s\\saopts.dat" ascii //weight: 1
        $x_1_3 = "Spytech SpyAgent" ascii //weight: 1
        $x_1_4 = "Client hook " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule MonitoringTool_Win32_SpyAgent_A_127691_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SpyAgent.A"
        threat_id = "127691"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4f 4c 45 41 43 43 2e 64 6c 6c [0-4] 3c 2f 48 54 4d 4c 3e}  //weight: 10, accuracy: Low
        $x_10_2 = "WM_HTML_GETOBJECT" ascii //weight: 10
        $x_10_3 = "NeoLite Executable File Compressor" ascii //weight: 10
        $x_1_4 = "GrabAOLURL" ascii //weight: 1
        $x_1_5 = "GrabBrowserURL" ascii //weight: 1
        $x_1_6 = "GrabFireFoxURL" ascii //weight: 1
        $x_1_7 = "GrabMSNSource" ascii //weight: 1
        $x_1_8 = "GrabSourceToFile" ascii //weight: 1
        $x_1_9 = "GrabSource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_SpyAgent_B_127692_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SpyAgent.B"
        threat_id = "127692"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Spytech" ascii //weight: 1
        $x_1_2 = "NeoWorx" ascii //weight: 1
        $x_1_3 = "KeystrokeCount" ascii //weight: 1
        $x_1_4 = "%s\\sacache\\skeys%d.log" ascii //weight: 1
        $x_1_5 = "_JournalProc@12" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_SpyAgent_D_127698_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SpyAgent.D"
        threat_id = "127698"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Spytech SpyAgent Keystroke" ascii //weight: 1
        $x_1_2 = "%ssacache\\skeys.log" ascii //weight: 1
        $x_1_3 = "--#BOUNDARY#" ascii //weight: 1
        $x_1_4 = "Content-Type: text/html; name=logs.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

