rule TrojanDownloader_Win32_Skreed_A_2147650390_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Skreed.A"
        threat_id = "2147650390"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Skreed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/dl/ex.php?" ascii //weight: 1
        $x_1_2 = {8b d8 56 53 ff 15 ?? ?? ?? ?? 53 89 45 08 ff d7 81 7d 08 01 04 00 00 73 0d 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 81 7d 08 00 04 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

