rule TrojanDownloader_Win32_Cophlap_A_2147602784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cophlap.A"
        threat_id = "2147602784"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cophlap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 04 01 00 00 8b ?? 50 ff 15 ?? ?? 40 00 8d 8c 24 ?? ?? 00 00 68 00 01 00 00 51 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 8d 4c 24}  //weight: 10, accuracy: Low
        $x_10_2 = {25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 [0-16] 10 59 2f b6 28 65 d1 11 96 11 00 00 f8 1e 0d 0d}  //weight: 10, accuracy: Low
        $x_10_3 = {40 00 8d 4c 24 ?? e8 ?? ?? 00 00 68 ?? ?? 40 00 8d 4c 24 ?? e8 ?? ?? 00 00 68 ?? ?? 40 00 8d 4c 24 ?? e8 ?? ?? 00 00 68 ?? ?? 40 00 8d 4c 24 ?? e8 ?? ?? 00 00 68 ?? ?? 40 00 8d 4c 24 ?? e8 ?? ?? 00 00}  //weight: 10, accuracy: Low
        $x_1_4 = "DeleteUrlCacheEntry" ascii //weight: 1
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_6 = "ShellExecuteA" ascii //weight: 1
        $x_1_7 = "Lockit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

