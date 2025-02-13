rule TrojanDownloader_Win32_Sality_AT_2147638115_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sality.AT"
        threat_id = "2147638115"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sality"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c1 00 04 00 00 89 8d ?? ?? ff ff 8b 95 ?? ?? ff ff 3b 95 ?? ?? ff ff 73 ?? 8d 85 ?? ?? ff ff 50 8b 0d ?? ?? ?? ?? 51 ff 15 ?? ?? ?? ?? 50 8b 15 ?? ?? ?? ?? 52 e8 ?? ?? ?? ?? 83 c4 0c 8d 85 ?? ?? ff ff 50 68 00 04 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

