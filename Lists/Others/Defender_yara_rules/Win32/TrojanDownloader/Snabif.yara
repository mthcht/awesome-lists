rule TrojanDownloader_Win32_Snabif_A_2147610596_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Snabif.A"
        threat_id = "2147610596"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Snabif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 66 61 62 69 61 6e 73 2e 63 6e 2f 68 62 2f [0-2] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "prcview" ascii //weight: 1
        $x_1_4 = "WinExec" ascii //weight: 1
        $x_1_5 = {f3 a5 66 a5 a4 b9 06 00 00 00 be ?? ?? 40 00 8d bd ?? ?? ff ff f3 a5 66 a5 a4 b9 06 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

