rule Worm_Win32_Yalove_A_2147601039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Yalove.A"
        threat_id = "2147601039"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Yalove"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 45 fc 8b cb ba ?? ?? ?? ?? e8 ?? ?? ff ff 68 02 00 00 80 8d 45 f8 8b 55 fc e8 ?? ?? ff ff 8b 45 f8 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? 8d 45 f8}  //weight: 10, accuracy: Low
        $x_10_2 = {68 02 00 00 80 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ff ff 68 02 00 00 80 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8d 95 ?? ?? ff ff a1 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 95 ?? ?? ff ff 8d 45 f4 b9 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 55 f4 a1 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 45 f4 e8 ?? ?? ff ff 6a 64}  //weight: 10, accuracy: Low
        $x_1_3 = "[AutoRun]" ascii //weight: 1
        $x_1_4 = "AUTORUN.INF" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Yalove_B_2147611048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Yalove.B"
        threat_id = "2147611048"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Yalove"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 41 75 74 6f 52 75 6e 5d [0-21] 6f 70 65 6e 3d [0-32] 73 68 65 6c 6c 65 78 65 63 75 74 65 3d [0-32] 73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d}  //weight: 1, accuracy: Low
        $x_1_2 = "Software\\Yahoo\\pager\\View\\YMSGR_buzz" wide //weight: 1
        $x_1_3 = "Software\\Yahoo\\pager\\View\\YMSGR_Launchcast" wide //weight: 1
        $x_1_4 = "ShowSuperHidden" wide //weight: 1
        $x_1_5 = "HideFileExt" wide //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_7 = "ShellExecuteW" ascii //weight: 1
        $x_1_8 = "NoDriveTypeAutoRun" wide //weight: 1
        $x_1_9 = "\\Startup" wide //weight: 1
        $x_1_10 = {8d 45 fc 8b cb ba ?? ?? ?? ?? e8 ?? ?? ff ff 68 02 00 00 80 8d 45 f8 8b 55 fc e8 ?? ?? ff ff 8b 45 f8 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? 8d 45 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

