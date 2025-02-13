rule TrojanDownloader_Win32_Autohoc_A_2147717110_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Autohoc.A!bit"
        threat_id = "2147717110"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Autohoc"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 72 6c 20 3a 3d 20 22 68 74 74 70 [0-48] 2e 6a 70 67}  //weight: 5, accuracy: Low
        $x_10_2 = "wins := \"user32.dll\\CallWindowProcW" ascii //weight: 10
        $x_10_3 = "DllCall(wins, \"Ptr\", &Mcode, \"str\", TargetHost, \"Ptr\", &bBuf, \"Uint\", 0, \"Uint\", 0)" ascii //weight: 10
        $x_2_4 = "FileCopy,%A_Scriptfullpath%, %A_Temp%\\%A_Scriptname%,1" ascii //weight: 2
        $x_2_5 = "FileSetAttrib, +SH, %A_Temp%\\%A_Scriptname%,1" ascii //weight: 2
        $x_1_6 = "RegWrite, REG_SZ, HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_7 = "FileCreateShortcut, \"%A_Temp%\\%A_ScriptName%\", %A_Startup%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

