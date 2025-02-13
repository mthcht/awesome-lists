rule Worm_Win32_Hooon_A_2147601746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Hooon.gen!A"
        threat_id = "2147601746"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Hooon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c0 83 ff 05 0f 95 c0 f7 d8 66 85 c0 74 45 8b 3d ?? ?? 40 00 8d 4d e4 68 ?? ?? 40 00 51 ff d7 8b 16 50 8d 45 e8 52 50 ff d7 50 e8 08 d9 ff ff ff 15}  //weight: 10, accuracy: Low
        $x_5_2 = {70 66 89 0d ?? ?? 40 00 e9 ?? ?? ff ff 68 ?? ?? 40 00 eb 34 8d 4d e4 8d 55 e8 51 52 6a 02 ff 15 ?? ?? 40 00 83 c4 0c 8d 4d e0 ff 15 ?? ?? 40 00}  //weight: 5, accuracy: Low
        $x_5_3 = "C:\\Documents and Settings\\Mustafa.MICROSOF-DEB140\\Desktop\\" wide //weight: 5
        $x_5_4 = "Designed By NoooH" ascii //weight: 5
        $x_1_5 = "start /b taskkill /f /im taskmgr.exe /im cmd.exe /im regedit.exe" wide //weight: 1
        $x_1_6 = "del /q C:\\WINDOWS\\system32\\KillAll.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

