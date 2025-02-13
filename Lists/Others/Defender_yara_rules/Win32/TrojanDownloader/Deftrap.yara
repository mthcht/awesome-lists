rule TrojanDownloader_Win32_Deftrap_A_2147683392_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Deftrap.A"
        threat_id = "2147683392"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Deftrap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3c 21 44 4f 43 54 59 50 45 00 00 00 72 62 00 00 77 62 00 00 53 76 63 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b}  //weight: 1, accuracy: High
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = {64 a1 18 00 00 00 8b 40 30 0f b6 40 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

