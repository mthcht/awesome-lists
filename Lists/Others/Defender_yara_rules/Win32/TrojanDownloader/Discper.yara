rule TrojanDownloader_Win32_Discper_A_2147695379_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Discper.A"
        threat_id = "2147695379"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Discper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%appdata%" wide //weight: 1
        $x_1_2 = "%TEMP%\\" wide //weight: 1
        $x_1_3 = ".exe" wide //weight: 1
        $x_1_4 = "open" wide //weight: 1
        $x_1_5 = "%s%x%x%x%x%s" wide //weight: 1
        $x_1_6 = "Internet Explorer" wide //weight: 1
        $x_4_7 = {33 45 d8 83 f7 7b 50 57 8d}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Discper_B_2147728002_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Discper.B!bit"
        threat_id = "2147728002"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Discper"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c9 74 2a 8b 55 ?? 0f b6 8c 15 ?? ?? ?? ?? 8b 45 ?? 99 be ?? ?? ?? ?? f7 fe 0f b6 54 15 ?? 33 ca 51 8b 45 ?? 50 8d 4d ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ec 8b 45 08 69 08 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 8b 55 08 89 0a 8b 45 08 8b 00 5d}  //weight: 1, accuracy: Low
        $x_1_3 = {55 8b ec 51 89 4d ?? 8b 45 ?? 8b 08 8b 55 08 8a 45 0c 88 04 11}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c4 04 33 d2 b9 ?? ?? ?? ?? f7 f1 81 c2 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 52 ff 15}  //weight: 1, accuracy: Low
        $x_1_5 = "Avast\\defs\\" wide //weight: 1
        $x_1_6 = "ping localhost -n 4 & del /F /Q" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

