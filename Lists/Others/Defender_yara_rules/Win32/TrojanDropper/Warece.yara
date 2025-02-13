rule TrojanDropper_Win32_Warece_A_2147599233_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Warece.A"
        threat_id = "2147599233"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Warece"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 4b fc ff ff 83 c4 24 33 c0 bb ?? ?? 00 00 80 b0 ?? ?? 40 00 ?? 40 3b c3 72 f4 8b 3d ?? ?? 40 00 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Warece_B_2147599827_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Warece.B"
        threat_id = "2147599827"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Warece"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\nvsvc1024.dll" ascii //weight: 1
        $x_1_2 = "del C:\\myapp.exe" ascii //weight: 1
        $x_1_3 = "if exist C:\\myapp.exe goto try" ascii //weight: 1
        $x_1_4 = "\\printer.exe" ascii //weight: 1
        $x_1_5 = "spoolvshell" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows NT\\CurrentVersion" ascii //weight: 1
        $x_1_7 = "wowfx.dll" ascii //weight: 1
        $x_1_8 = "_trayEvent" ascii //weight: 1
        $x_1_9 = "ShellExecuteExA" ascii //weight: 1
        $x_1_10 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_11 = "\\nvsvc1024.dll" wide //weight: 1
        $x_10_12 = {8d 85 ec fc ff ff 6a 1a 50 56 ff 15 ?? ?? 40 00 8d 85 ec fc ff ff 50 8d 85 f4 fe ff ff 50 e8 ?? ?? 00 00 8d 85 f4 fe ff ff 68 ?? ?? 40 00 50 e8 ?? ?? 00 00 8d 85 ec fc ff ff 50 8d 85 f0 fd ff ff 50 e8 ?? ?? 00 00 8d 85 f0 fd ff ff 68 ?? ?? 40 00 50 e8 ?? ?? 00 00 68 ?? ?? 40 00 e8 ?? ?? ff ff 83 c4 24 33 c0 bb 00 26 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

