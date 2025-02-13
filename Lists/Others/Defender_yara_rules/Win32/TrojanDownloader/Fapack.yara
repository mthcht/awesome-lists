rule TrojanDownloader_Win32_Fapack_A_2147630770_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fapack.A"
        threat_id = "2147630770"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fapack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 00 6a 00 ff d6 ff d7 0b c0 75 54 8d 85 ?? ?? 00 00 50 ff 95 ?? ?? 00 00 0b c0 74 43 68 99 23 5d d9 50 e8 ?? ?? ff ff 0b c0 74 34 8b f8 68 ad 6d bf e8 53 e8 ?? ?? ff ff 0b c0 74 23 8b f0 6a 00 6a 00 8d 85 ?? ?? 00 00 50 8d 85 ?? ?? 00 00 50 6a 00 ff d7 6a 00 8d 85 ?? ?? 00 00 50 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

