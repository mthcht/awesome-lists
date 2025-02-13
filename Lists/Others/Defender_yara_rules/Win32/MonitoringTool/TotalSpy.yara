rule MonitoringTool_Win32_TotalSpy_17559_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/TotalSpy"
        threat_id = "17559"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "TotalSpy"
        severity = "6"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "uninstall Total Spy" ascii //weight: 1
        $x_1_3 = "Clear all spy result files from hard drive" ascii //weight: 1
        $x_1_4 = "\\spy_screenshots" ascii //weight: 1
        $x_1_5 = "SetClipboardViewer" ascii //weight: 1
        $x_1_6 = "GetClipboardData" ascii //weight: 1
        $x_1_7 = "CloseClipboard" ascii //weight: 1
        $x_1_8 = "EmptyClipboard" ascii //weight: 1
        $x_1_9 = "GetKeyboardState" ascii //weight: 1
        $x_1_10 = "GetKeyNameTextA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_TotalSpy_17559_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/TotalSpy"
        threat_id = "17559"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "TotalSpy"
        severity = "6"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Start program in Hidden mode (hide tray icon)" ascii //weight: 1
        $x_1_2 = "Hidden mode hotkey" ascii //weight: 1
        $x_1_3 = "Apply && Spy" ascii //weight: 1
        $x_1_4 = "Invisibility Settings" ascii //weight: 1
        $x_1_5 = "This application uses a HACKED version of the ABF software, Inc. product." ascii //weight: 1
        $x_2_6 = "gaavt procram in oidcen mode chide rrae iwyn)" ascii //weight: 2
        $x_1_7 = "Hiddew crte hhttey" ascii //weight: 1
        $x_1_8 = "Appiyvz&eSly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_TotalSpy_17559_2
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/TotalSpy"
        threat_id = "17559"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "TotalSpy"
        severity = "6"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Invisibility Settings" wide //weight: 1
        $x_1_2 = "Free Key_logger" ascii //weight: 1
        $x_1_3 = "\\FKMR Manager\\cnf.dat" wide //weight: 1
        $x_1_4 = "No screenshots for picked date." ascii //weight: 1
        $x_1_5 = "Visited websites" ascii //weight: 1
        $x_1_6 = "Keystroke logging" ascii //weight: 1
        $x_1_7 = "Invisible monitoring is starting." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

