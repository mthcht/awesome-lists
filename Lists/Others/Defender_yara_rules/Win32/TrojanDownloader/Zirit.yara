rule TrojanDownloader_Win32_Zirit_A_2147602924_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zirit.A"
        threat_id = "2147602924"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zirit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c2 28 8b 02 03 05 ?? ?? ?? 00 c7 44 24 28 ?? ?? ?? 00 ff e0 61 6a 00 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 03 00 00 00 8b 06 35 0d 0d 0d 0d 89 06 83 c6 04 e2 f2 be ?? ?? ?? 00 b9 0c 00 00 00 f3 a4 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 68 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 a3 ?? ?? ?? 00 6a 02 6a 00 6a fc ff 35 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

