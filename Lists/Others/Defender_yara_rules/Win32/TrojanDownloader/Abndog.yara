rule TrojanDownloader_Win32_Abndog_A_2147617045_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Abndog.A"
        threat_id = "2147617045"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Abndog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 b8 22 00 00 ff d7 6a 00 8d 44 24 10 6a 00 8d 8c 24 18 01 00 00 50 51 6a 00 e8 ?? ?? 00 00 85 c0 75 d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

