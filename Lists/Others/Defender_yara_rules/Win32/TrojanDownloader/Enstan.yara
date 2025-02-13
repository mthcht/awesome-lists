rule TrojanDownloader_Win32_Enstan_A_2147654705_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Enstan.A"
        threat_id = "2147654705"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Enstan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 3c 00 74 ?? c1 0d ?? ?? 40 00 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {68 c7 69 9b fa 68 ?? ?? 40 00 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {68 66 57 38 ef 68 ?? ?? 40 00 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

