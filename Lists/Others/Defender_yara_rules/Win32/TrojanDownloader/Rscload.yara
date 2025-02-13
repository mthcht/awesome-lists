rule TrojanDownloader_Win32_Rscload_A_2147628492_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rscload.A"
        threat_id = "2147628492"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rscload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rtlasyvq" ascii //weight: 1
        $x_1_2 = "tkbqbhor" ascii //weight: 1
        $x_1_3 = {b8 00 00 00 80 ff 74 24 64 88 1d ?? ?? ?? 00 53 53 68 d8 01 00 00 68 17 01 00 00 50 50 68 00 00 08 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 00 02 00 00 ff 15 ?? ?? ?? 00 39 1d ?? ?? ?? 00 8b f8 74 1c 39 1d ?? ?? ?? 00 74 14 ff 35 ?? ?? ?? 00 56 68 ?? ?? ?? 00 e8 ab 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

