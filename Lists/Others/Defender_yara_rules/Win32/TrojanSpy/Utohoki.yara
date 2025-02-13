rule TrojanSpy_Win32_Utohoki_A_2147689223_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Utohoki.A"
        threat_id = "2147689223"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Utohoki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#InstallKeybdHook" ascii //weight: 1
        $x_1_2 = "#InstallMouseHook" ascii //weight: 1
        $x_1_3 = "FileCopy,%A_ScriptFullPath%,%A_AppData%\\Microsoft\\Office\\ctfmon.exe" ascii //weight: 1
        $x_1_4 = "\\CurrentVersion\\Run,Microsoft Text Services,%A_AppData%\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

