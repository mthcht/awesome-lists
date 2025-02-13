rule TrojanDownloader_Win32_Zerok_A_2147647985_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zerok.A"
        threat_id = "2147647985"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zerok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://r.zerotime.kr/" wide //weight: 5
        $x_1_2 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_3 = "\\vip\\Desktop\\" wide //weight: 1
        $x_1_4 = "/run.php?m" wide //weight: 1
        $x_1_5 = "/update.txt" wide //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

