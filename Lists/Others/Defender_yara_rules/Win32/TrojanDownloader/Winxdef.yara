rule TrojanDownloader_Win32_Winxdef_A_2147603390_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Winxdef.A"
        threat_id = "2147603390"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Winxdef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 57 68 98 63 40 00 6a 00 6a 00 ff 15 50 60 40 00 8b f0 ff 15 b8 60 40 00 3d b7 00 00 00 75 04 33 ff eb 06 8b c6 33 f6 8b f8 85 f6 74 07 56 ff 15 a4 60 40 00 8b c7 5f 5e c3}  //weight: 1, accuracy: High
        $x_1_2 = {ff 15 3c 61 40 00 a3 c8 81 40 00}  //weight: 1, accuracy: High
        $x_1_3 = {83 3d c8 81 40 00 00 75 08 6a 01 e8 0d 05 00 00 59 68 09 04 00 c0 ff 15 30 61 40 00 50 ff 15 2c 61 40 00 c9 c3}  //weight: 1, accuracy: High
        $x_1_4 = "http://scanner.winxdefender.com/" ascii //weight: 1
        $x_1_5 = "Software\\WinXDefender" ascii //weight: 1
        $x_1_6 = "http://download.winxdefender.com/" ascii //weight: 1
        $x_1_7 = "%PROGRAMFILES%\\WinXDefender\\WinXDefender.exe" ascii //weight: 1
        $x_1_8 = "ShellExecuteW" ascii //weight: 1
        $x_1_9 = "URLOpenStreamW" ascii //weight: 1
        $x_1_10 = "CreateMutexW" ascii //weight: 1
        $x_1_11 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

