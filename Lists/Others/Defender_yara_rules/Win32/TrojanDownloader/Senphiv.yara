rule TrojanDownloader_Win32_Senphiv_A_2147630248_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Senphiv.A"
        threat_id = "2147630248"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Senphiv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 00 3f 00 ?? 6a 74 68 00 01 00 00 ?? e8 ?? ?? ff ff e8 ?? ?? ff ff 68 ?? ?? ?? ?? eb 09}  //weight: 1, accuracy: Low
        $x_1_2 = {66 b9 59 00 e8 ?? ?? ?? ?? 8b 4d ?? 88 01 66 b9 58 00}  //weight: 1, accuracy: Low
        $x_1_3 = {00 6d 43 68 61 6e 67 65 49 45 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

