rule TrojanDownloader_Win32_Kishop_A_2147682611_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Kishop.A"
        threat_id = "2147682611"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Kishop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 5b 64 69 72 73 78 36 34 5d 00}  //weight: 1, accuracy: High
        $x_1_2 = {3b 45 0c 73 21 8b 45 ?? 8a 00 34 ?? 8b 4d ?? 88 01 8b 45 ?? 8a 00 34 ?? 8b 4d ?? 88 01 8b 45 ?? 40 89 45 ?? eb d0 c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

