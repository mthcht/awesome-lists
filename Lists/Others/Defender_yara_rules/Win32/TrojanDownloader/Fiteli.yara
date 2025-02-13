rule TrojanDownloader_Win32_Fiteli_A_2147607516_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fiteli.A"
        threat_id = "2147607516"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fiteli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 89 b5 cc ad ff ff e9 7c ff ff ff 53 8b 1d ?? ?? 40 00 ff d3 83 c4 04 8d 95 ?? ?? ff ff 52 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {e9 80 00 00 00 8d 55 e4 8d 8d e0 fb ff ff e8 ?? ?? ff ff 85 c0 74 6e ba 01 00 00 00 8b 8d e0 fb ff ff e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

