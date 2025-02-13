rule MonitoringTool_Win32_PersonalInspector_18080_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PersonalInspector"
        threat_id = "18080"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PersonalInspector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InstallKeyboardHook" ascii //weight: 1
        $x_2_2 = "[PRINTSCREEN]" ascii //weight: 2
        $x_3_3 = "SOFTWARE\\KMiNT21\\PersonalInspector" ascii //weight: 3
        $x_2_4 = "\\inspector.rep" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_PersonalInspector_18080_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/PersonalInspector"
        threat_id = "18080"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PersonalInspector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Personal Inspector" ascii //weight: 1
        $x_1_2 = "KMiNT21 Software" ascii //weight: 1
        $x_1_3 = "Software\\KMiNT21\\PersonalInspector" ascii //weight: 1
        $x_1_4 = "svcmon.dll" ascii //weight: 1
        $x_1_5 = "svcmon.exe" ascii //weight: 1
        $x_1_6 = "rview.exe" ascii //weight: 1
        $x_1_7 = "SetClipboardData" ascii //weight: 1
        $x_1_8 = "TrackPopupMenu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

