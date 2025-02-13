rule TrojanDownloader_Win32_Rugzip_A_2147618173_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugzip.A"
        threat_id = "2147618173"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugzip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Accept-Language: ru" wide //weight: 1
        $x_1_2 = "Accept-Encoding: gzip, deflate" wide //weight: 1
        $x_10_3 = {c8 00 00 00 8b f8 0f 85 ?? ?? 00 00 3b fb 0f 84 ?? ?? 00 00 8b 45 ?? 80 38 4d 0f 85 ?? ?? 00 00 80 78 01 5a 0f 85 ?? ?? 00 00 8d 45 ?? 6a 08 50 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

